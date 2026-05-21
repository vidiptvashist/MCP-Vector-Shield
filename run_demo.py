import os
import sys
import time
import json
import httpx
import uvicorn
import multiprocessing
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse

# Define Mock Upstream Server
upstream_app = FastAPI()

MOCK_RESPONSE = {
    "jsonrpc": "2.0",
    "result": {
        "tools": [
            {
                "name": "read_file",
                "description": "Reads contents of a file safely.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            },
            {
                "name": "system_exec_shell",
                "description": "Execute arbitrary shell commands.",
                "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}
            },
            {
                "name": "add_numbers",
                "description": "Add two numbers.",
                "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}
            }
        ]
    },
    "id": "demo-id"
}

@upstream_app.post("/mcp")
async def handle_post():
    return JSONResponse(content=MOCK_RESPONSE)

@upstream_app.get("/sse")
async def handle_sse():
    async def sse_generator():
        # First send endpoint message (standard MCP SSE protocol)
        yield "event: endpoint\ndata: http://localhost:8081/mcp\n\n"
        # Then send the tools list message
        yield f"event: message\ndata: {json.dumps(MOCK_RESPONSE)}\n\n"
        # Then heartbeat
        yield "event: heartbeat\ndata: {}\n\n"
    return StreamingResponse(sse_generator(), media_type="text/event-stream")


def run_upstream():
    uvicorn.run(upstream_app, host="127.0.0.1", port=8081, log_level="error")


def run_proxy(block_mode=False):
    # Set environments for proxy config
    os.environ["MCP_UPSTREAM_URL"] = "http://localhost:8081"
    os.environ["MCP_BLOCK_MODE"] = "true" if block_mode else "false"
    
    # Import the proxy app dynamically so env vars are read
    from mcp_vector_shield.proxy import app as proxy_app
    port = 8083 if block_mode else 8082
    uvicorn.run(proxy_app, host="127.0.0.1", port=port, log_level="error")


def print_title(title: str):
    print("\n" + "=" * 60)
    print(f" {title} ".center(60, "="))
    print("=" * 60)


if __name__ == "__main__":
    # Start Mock Server
    p_upstream = multiprocessing.Process(target=run_upstream)
    p_upstream.start()

    # Start Filter Proxy (Port 8082)
    p_proxy_filter = multiprocessing.Process(target=run_proxy, args=(False,))
    p_proxy_filter.start()

    # Start Block Proxy (Port 8083)
    p_proxy_block = multiprocessing.Process(target=run_proxy, args=(True,))
    p_proxy_block.start()

    # Give uvicorn servers time to boot
    time.sleep(6.0)

    try:
        # 1. Test Filter Proxy (JSON Payload)
        print_title("1. FILTER MODE - JSON Response (Proxy Port 8082)")
        print("Sending POST request to Proxy on /mcp...")
        res = httpx.post("http://localhost:8082/mcp")
        print(f"Status Code: {res.status_code}")
        print("Response Body:")
        print(json.dumps(res.json(), indent=2))

        # 2. Test Filter Proxy (SSE stream Payload)
        print_title("2. FILTER MODE - SSE Stream Response (Proxy Port 8082)")
        print("Sending GET request to Proxy on /sse...")
        with httpx.stream("GET", "http://localhost:8082/sse") as stream:
            for line in stream.iter_lines():
                if line.strip():
                    print(line)

        # 3. Test Block Proxy (JSON Payload)
        print_title("3. BLOCK MODE - JSON Response (Proxy Port 8083)")
        print("Sending POST request to Block Proxy on /mcp...")
        res = httpx.post("http://localhost:8083/mcp")
        print(f"Status Code: {res.status_code}")
        print("Response Body:")
        print(json.dumps(res.json(), indent=2))

        # 4. Test Block Proxy (SSE Stream Payload)
        print_title("4. BLOCK MODE - SSE Stream Response (Proxy Port 8083)")
        print("Sending GET request to Block Proxy on /sse...")
        with httpx.stream("GET", "http://localhost:8083/sse") as stream:
            for line in stream.iter_lines():
                if line.strip():
                    print(line)

    except Exception as e:
        print(f"Error during demo: {e}", file=sys.stderr)
        
    finally:
        # Ensure we terminate all background processes cleanly
        print_title("Shutting down servers...")
        p_upstream.terminate()
        p_proxy_filter.terminate()
        p_proxy_block.terminate()
        
        p_upstream.join()
        p_proxy_filter.join()
        p_proxy_block.join()
        print("Demo clean shutdown completed.")
