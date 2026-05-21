import json
import pytest
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, JSONResponse
from httpx import AsyncClient, ASGITransport

from mcp_vector_shield.middleware import MCPVectorShieldMiddleware

# Mock payloads
MOCK_TOOLS_RESPONSE = {
    "jsonrpc": "2.0",
    "result": {
        "tools": [
            {
                "name": "calculator",
                "description": "Performs basic arithmetic.",
                "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}},
            },
            {
                "name": "dangerous_exec_shell",
                "description": "Execute system command on the host.",
                "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
            },
            {
                "name": "safe_fetch_weather",
                "description": "Fetches current weather for a city.",
                "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
            },
        ]
    },
    "id": "test-id-123",
}


# Helper to create a test app with configured middleware
def create_test_app(block_mode=False, use_http_403_for_block=False):
    app = FastAPI()

    app.add_middleware(
        MCPVectorShieldMiddleware,
        block_mode=block_mode,
        use_http_403_for_block=use_http_403_for_block,
    )

    @app.post("/mcp/json")
    async def json_endpoint():
        return JSONResponse(content=MOCK_TOOLS_RESPONSE)

    @app.get("/mcp/sse")
    async def sse_endpoint():
        async def generator():
            # Send the tools list response
            yield f"event: message\ndata: {json.dumps(MOCK_TOOLS_RESPONSE)}\n\n"
            # Send an unrelated heartbeat event
            yield "event: heartbeat\ndata: {}\n\n"

        return StreamingResponse(generator(), media_type="text/event-stream")

    @app.get("/other/json")
    async def other_json():
        # A normal JSON endpoint not containing tools/list
        return JSONResponse(content={"status": "ok", "message": "hello world"})

    return app


@pytest.mark.asyncio
async def test_filter_mode_json():
    """
    Test that the middleware strips the malicious tool in FILTER mode (default)
    for a standard JSON response.
    """
    app = create_test_app(block_mode=False)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/mcp/json")
        assert response.status_code == 200
        data = response.json()

        # Verify the result contains only the non-malicious tools
        tools = data["result"]["tools"]
        assert len(tools) == 2
        tool_names = [t["name"] for t in tools]
        assert "calculator" in tool_names
        assert "safe_fetch_weather" in tool_names
        assert "dangerous_exec_shell" not in tool_names


@pytest.mark.asyncio
async def test_block_mode_json_rpc_error():
    """
    Test that the middleware returns a JSON-RPC error when a malicious tool is found
    in BLOCK mode (without HTTP 403).
    """
    app = create_test_app(block_mode=True, use_http_403_for_block=False)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/mcp/json")
        assert response.status_code == 200
        data = response.json()

        # Verify it has JSON-RPC error structure
        assert "error" in data
        assert data["error"]["code"] == -32000
        assert "Access denied" in data["error"]["message"]
        assert data["id"] == "test-id-123"
        assert "result" not in data


@pytest.mark.asyncio
async def test_block_mode_http_403():
    """
    Test that the middleware returns an HTTP 403 Forbidden when a malicious tool is found
    in BLOCK mode with HTTP 403 enabled.
    """
    app = create_test_app(block_mode=True, use_http_403_for_block=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/mcp/json")
        assert response.status_code == 403
        data = response.json()
        assert "error" in data
        assert "Access Denied" in data["error"]


@pytest.mark.asyncio
async def test_filter_mode_sse():
    """
    Test that the middleware intercepts and filters tools from an SSE stream.
    """
    app = create_test_app(block_mode=False)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        async with ac.stream("GET", "/mcp/sse") as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]

            # Read and reconstruct events
            events = []
            async for line in response.aiter_lines():
                if line.strip():
                    events.append(line)

            # We expect a message event followed by a heartbeat event
            assert len(events) >= 2

            # Find the message event data line
            msg_data_line = [e for e in events if e.startswith("data:") and "tools" in e][0]
            data_json = json.loads(msg_data_line.split("data:")[1].strip())

            tools = data_json["result"]["tools"]
            assert len(tools) == 2
            tool_names = [t["name"] for t in tools]
            assert "calculator" in tool_names
            assert "safe_fetch_weather" in tool_names
            assert "dangerous_exec_shell" not in tool_names


@pytest.mark.asyncio
async def test_block_mode_sse():
    """
    Test that the middleware intercepts and replaces tools list event with a JSON-RPC error
    inside an SSE stream when in BLOCK mode.
    """
    app = create_test_app(block_mode=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        async with ac.stream("GET", "/mcp/sse") as response:
            assert response.status_code == 200

            events = []
            async for line in response.aiter_lines():
                if line.strip():
                    events.append(line)

            # Verify the response payload has been converted into a JSON-RPC error
            msg_data_line = [e for e in events if e.startswith("data:") and "error" in e][0]
            data_json = json.loads(msg_data_line.split("data:")[1].strip())

            assert "error" in data_json
            assert data_json["error"]["code"] == -32000
            assert "Access denied" in data_json["error"]["message"]
            assert "result" not in data_json


@pytest.mark.asyncio
async def test_passthrough_behavior():
    """
    Test that other requests/responses that do not contain tools/list are left untouched.
    """
    app = create_test_app(block_mode=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/other/json")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["message"] == "hello world"
