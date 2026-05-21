import json
import codecs
import logging
from typing import Callable, Optional, Any

logger = logging.getLogger("mcp_vector_shield")


class ShieldMiddleware:
    """
    Native MCP Middleware for the Python `FastMCP` framework.
    Intercepts tools list definitions and validates them against the MCPSemanticRegistry
    to block or filter out shadowing attacks (name-squatting, malicious revisions) in-flight.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        block_mode: bool = False,
    ):
        """
        :param registry: An instance of `MCPSemanticRegistry`. If None, initializes a default instance.
        :param block_mode: If True, raises an exception/error to block the entire tools/list request when an attack is found.
                           If False, filters (strips) only the malicious tools and lets the safe ones through.
        """
        self.block_mode = block_mode
        if registry is None:
            from mcp_vector_shield.mcp_registry import MCPSemanticRegistry

            self.registry = MCPSemanticRegistry(distance_threshold=0.05)
        else:
            self.registry = registry

    def attach(self, mcp: Any) -> None:
        """
        Attach the middleware to a FastMCP server instance.
        """
        orig_list_tools = mcp.list_tools

        async def wrapped_list_tools() -> list[Any]:
            tools = await orig_list_tools()
            filtered_tools = []
            for tool in tools:
                # Resolve the schema dictionary
                # FastMCP list_tools returns a list of MCPTool / Tool objects
                # which have attributes: name, description, inputSchema
                tool_schema = {
                    "name": getattr(tool, "name", ""),
                    "description": getattr(tool, "description", "") or "",
                    "inputSchema": getattr(tool, "inputSchema", {})
                    or getattr(tool, "parameters", {})
                    or {},
                }

                # Run shadowing attack detection using FAISS Registry
                if self.registry.is_shadowing_attack(tool_schema):
                    logger.warning(
                        f"[ShieldMiddleware] Security Block: Tool '{tool.name}' is flagged as a SHADOWING ATTACK!"
                    )
                    if self.block_mode:
                        raise ValueError(
                            f"Access Denied: Unsafe shadow tool modification detected on '{tool.name}'."
                        )
                    continue

                filtered_tools.append(tool)
            return filtered_tools

        # Wrap list_tools method on the FastMCP instance
        mcp.list_tools = wrapped_list_tools

        # Re-register the handler on the underlying protocol server
        if hasattr(mcp, "_mcp_server"):
            mcp._mcp_server.list_tools()(wrapped_list_tools)


class MCPVectorShieldMiddleware:
    """
    ASGI middleware that intercepts Model Context Protocol (MCP) JSON-RPC responses.
    Specifically intercepts the `tools/list` response payload (both JSON and SSE streams),
    runs a verification hook on each tool, and strips/blocks malicious tool definitions.
    """

    def __init__(
        self,
        app,
        verify_hook: Optional[Callable[[dict], bool]] = None,
        block_mode: bool = False,
        use_http_403_for_block: bool = False,
    ):
        """
        :param app: The ASGI application.
        :param verify_hook: Callable that accepts a tool schema dict and returns a boolean (True if safe, False if unsafe).
                            Defaults to the verification hook in mcp_vector_shield.verify.
        :param block_mode: If True, blocks the entire response when an unsafe tool is found.
                           If False, strips the unsafe tool from the tools array but allows the rest through.
        :param use_http_403_for_block: If True and block_mode is True, returns an HTTP 403 Forbidden.
                                       Otherwise returns a JSON-RPC error response object.
        """
        self.app = app
        if verify_hook is None:
            from mcp_vector_shield.verify import verify_tool_metadata

            self.verify_hook = verify_tool_metadata
        else:
            self.verify_hook = verify_hook

        self.block_mode = block_mode
        self.use_http_403_for_block = use_http_403_for_block

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        should_intercept = False
        response_started = False
        status_code = 200
        headers = []
        content_type = ""
        body_buffer = bytearray()

        # Incremental UTF-8 decoder for streaming text/event-stream
        decoder = codecs.getincrementaldecoder("utf-8")()
        sse_buffer = ""

        async def intercept_send(message):
            nonlocal should_intercept, response_started, status_code, headers, content_type, sse_buffer

            message_type = message["type"]

            if message_type == "http.response.start":
                status_code = message["status"]
                headers = message["headers"]
                # Extract content-type case-insensitively
                for k, v in headers:
                    if k.lower() == b"content-type":
                        content_type = v.decode("utf-8", errors="ignore").lower()
                        break

                # Check if we should intercept
                should_intercept = (
                    "application/json" in content_type or "text/event-stream" in content_type
                )

                if not should_intercept:
                    response_started = True
                    await send(message)
                return

            elif message_type == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)

                # Pass-through if not intercepted
                if not should_intercept:
                    await send(message)
                    return

                # Handle Server-Sent Events (SSE)
                if "text/event-stream" in content_type:
                    if not response_started:
                        response_started = True
                        await send(
                            {
                                "type": "http.response.start",
                                "status": status_code,
                                "headers": headers,
                            }
                        )

                    if body:
                        try:
                            # Decode incoming bytes stream
                            sse_buffer += decoder.decode(body, final=not more_body)
                        except Exception as e:
                            logger.error(f"Error decoding SSE UTF-8 stream: {e}")
                            await send(message)
                            return

                        # Process SSE events separated by double newlines
                        # Normalize line endings to simplify split logic
                        normalized = sse_buffer.replace("\r\n", "\n").replace("\r", "\n")
                        parts = normalized.split("\n\n")

                        # Keep the incomplete last part in buffer
                        sse_buffer = parts[-1]
                        complete_events = parts[:-1]

                        modified_parts = []
                        for event_str in complete_events:
                            if not event_str.strip():
                                modified_parts.append(event_str + "\n\n")
                                continue

                            modified_event = self._process_sse_event(event_str)
                            modified_parts.append(modified_event + "\n\n")

                        if modified_parts:
                            modified_body = "".join(modified_parts).encode("utf-8")
                            await send(
                                {
                                    "type": "http.response.body",
                                    "body": modified_body,
                                    "more_body": more_body,
                                }
                            )
                        elif not more_body:
                            await send(
                                {"type": "http.response.body", "body": b"", "more_body": False}
                            )
                    else:
                        if not more_body:
                            await send(message)
                    return

                # Handle Standard JSON Response
                if "application/json" in content_type:
                    body_buffer.extend(body)

                    if not more_body:
                        # Full body buffered, process it
                        modified_body = self._process_json_body(body_buffer)

                        is_blocked = False
                        if self.block_mode and self.use_http_403_for_block:
                            try:
                                data = json.loads(body_buffer.decode("utf-8"))
                                if self._has_malicious_tools(data):
                                    is_blocked = True
                            except Exception:
                                pass

                        if is_blocked:
                            status_code = 403
                            modified_body = json.dumps(
                                {
                                    "error": "Access Denied: Unsafe/unauthorized tool metadata detected by proxy."
                                }
                            ).encode("utf-8")

                            # Clean and rebuild headers
                            new_headers = []
                            for k, v in headers:
                                if k.lower() not in (b"content-length", b"content-type"):
                                    new_headers.append((k, v))
                            new_headers.append((b"content-type", b"application/json"))
                            new_headers.append(
                                (b"content-length", str(len(modified_body)).encode("utf-8"))
                            )
                            headers = new_headers
                        else:
                            # Standard JSON adjustment
                            new_headers = []
                            for k, v in headers:
                                if k.lower() != b"content-length":
                                    new_headers.append((k, v))
                            new_headers.append(
                                (b"content-length", str(len(modified_body)).encode("utf-8"))
                            )
                            headers = new_headers

                        response_started = True
                        await send(
                            {
                                "type": "http.response.start",
                                "status": status_code,
                                "headers": headers,
                            }
                        )
                        await send(
                            {
                                "type": "http.response.body",
                                "body": modified_body,
                                "more_body": False,
                            }
                        )
                    return

        await self.app(scope, receive, intercept_send)

    def _has_malicious_tools(self, data: dict) -> bool:
        """
        Check if the JSON payload contains any tool that fails verification.
        """
        if not isinstance(data, dict):
            return False

        if "result" in data:
            result = data["result"]
            if isinstance(result, dict) and "tools" in result:
                tools = result["tools"]
                if isinstance(tools, list):
                    for tool in tools:
                        if not self.verify_hook(tool):
                            return True
        return False

    def _process_json_body(self, body_bytes: bytes) -> bytes:
        """
        Parses JSON body, intercepts tools/list and filters or blocks malicious tools.
        """
        try:
            body_str = body_bytes.decode("utf-8")
            data = json.loads(body_str)
        except Exception as e:
            logger.error(f"Failed to parse JSON body: {e}")
            return body_bytes

        if isinstance(data, dict) and "result" in data:
            result = data["result"]
            if isinstance(result, dict) and "tools" in result:
                tools = result["tools"]
                if isinstance(tools, list):
                    filtered_tools = []
                    has_malicious = False
                    for tool in tools:
                        if self.verify_hook(tool):
                            filtered_tools.append(tool)
                        else:
                            has_malicious = True

                    if has_malicious:
                        if self.block_mode:
                            if not self.use_http_403_for_block:
                                # Return standard JSON-RPC error response
                                error_response = {
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32000,
                                        "message": "Access denied: Suspicious tool metadata blocked by proxy",
                                    },
                                    "id": data.get("id"),
                                }
                                return json.dumps(error_response).encode("utf-8")
                        else:
                            # Filter mode: replace with filtered tools
                            result["tools"] = filtered_tools
                            data["result"] = result
                            return json.dumps(data).encode("utf-8")

        return body_bytes

    def _process_sse_event(self, event_str: str) -> str:
        """
        Parses a single SSE event, finds tools/list response payload, and filters/blocks it.
        """
        lines = event_str.split("\n")
        data_lines = []
        other_lines = []
        for line in lines:
            if line.startswith("data:"):
                val = line[5:]
                if val.startswith(" "):
                    val = val[1:]
                data_lines.append(val)
            else:
                other_lines.append(line)

        if not data_lines:
            return event_str

        data_content = "\n".join(data_lines)
        try:
            data_json = json.loads(data_content)
        except Exception:
            # Not valid JSON
            return event_str

        if isinstance(data_json, dict) and "result" in data_json:
            result = data_json["result"]
            if isinstance(result, dict) and "tools" in result:
                tools = result["tools"]
                if isinstance(tools, list):
                    filtered_tools = []
                    has_malicious = False
                    for tool in tools:
                        if self.verify_hook(tool):
                            filtered_tools.append(tool)
                        else:
                            has_malicious = True

                    if has_malicious:
                        if self.block_mode:
                            error_payload = {
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32000,
                                    "message": "Access denied: Suspicious tool metadata blocked by proxy",
                                },
                                "id": data_json.get("id"),
                            }
                            new_lines = [line for line in other_lines if line]
                            new_lines.append(f"data: {json.dumps(error_payload)}")
                            return "\n".join(new_lines)
                        else:
                            result["tools"] = filtered_tools
                            data_json["result"] = result
                            new_lines = [line for line in other_lines if line]
                            new_lines.append(f"data: {json.dumps(data_json)}")
                            return "\n".join(new_lines)

        return event_str
