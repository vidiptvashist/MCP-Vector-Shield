import os
import json
import httpx
import logging
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from mcp_vector_shield.middleware import MCPVectorShieldMiddleware

logger = logging.getLogger("mcp_vector_shield")

# Read target upstream server config from environment
UPSTREAM_URL = os.getenv("MCP_UPSTREAM_URL", "http://localhost:8000").rstrip("/")
BLOCK_MODE = os.getenv("MCP_BLOCK_MODE", "false").lower() in ("true", "1", "yes")
USE_HTTP_403 = os.getenv("MCP_USE_HTTP_403", "false").lower() in ("true", "1", "yes")

app = FastAPI(
    title="MCP Vector Shield Proxy",
    description="A security proxy for filtering Model Context Protocol (MCP) JSON-RPC tools metadata.",
)

# Register the Vector Shield Middleware
app.add_middleware(
    MCPVectorShieldMiddleware, block_mode=BLOCK_MODE, use_http_403_for_block=USE_HTTP_403
)

# Async HTTP Client configuration
# We configure a long timeout suitable for MCP SSE connections
http_client = httpx.AsyncClient(
    base_url=UPSTREAM_URL, timeout=httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=None)
)


@app.on_event("shutdown")
async def shutdown_event():
    await http_client.aclose()


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def proxy_route(request: Request, path: str):
    """
    Catch-all route that proxies incoming HTTP / JSON-RPC / SSE traffic
    to the upstream MCP Server.
    """
    url = f"/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Forward all request headers except Host & Content-Length (handled by httpx)
    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")
    }

    # Fetch request body
    body = await request.body()

    try:
        # Build request to upstream MCP Server
        req = http_client.build_request(
            method=request.method, url=url, headers=headers, content=body
        )

        # Send streaming request to support SSE streams and chunked JSON
        response = await http_client.send(req, stream=True)

        async def stream_generator():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            finally:
                await response.aclose()

        # Build response headers, removing transport/framing specific headers
        res_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() not in ("content-length", "transfer-encoding")
        }

        return StreamingResponse(
            stream_generator(),
            status_code=response.status_code,
            headers=res_headers,
            media_type=response.headers.get("content-type"),
        )

    except httpx.RequestError as exc:
        logger.error(f"Upstream request failure: {exc}")
        return Response(
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": f"Proxy upstream connection error: {str(exc)}",
                    },
                    "id": None,
                }
            ),
            status_code=502,
            media_type="application/json",
        )
