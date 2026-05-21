import sys
import os
import json
import argparse
import asyncio
import logging
from typing import List

# Pre-initialize environment thread patching for FAISS Apple Silicon optimization
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

# Configure logging to stderr so it doesn't pollute stdout JSON-RPC stream
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp_shield_passthrough")


async def connect_stdin() -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


async def connect_stdout() -> asyncio.StreamWriter:
    loop = asyncio.get_event_loop()
    w_transport, w_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, None, loop)
    return writer


async def pipe_stdin_to_sub(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Forwards stdin lines from the editor directly to the subprocess stdin.
    """
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            writer.write(line)
            await writer.drain()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error piping stdin to subprocess: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def pipe_sub_to_stdout(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    registry,
    block_mode: bool,
):
    """
    Reads stdout lines from the subprocess, audits tools/list JSON-RPC payloads, and forwards safe streams back to the editor.
    """
    try:
        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break

            line_str = line_bytes.decode("utf-8", errors="ignore")
            # Intercept JSON-RPC payload of tools/list
            if '"result"' in line_str and '"tools"' in line_str:
                try:
                    data = json.loads(line_str.strip())
                    if (
                        isinstance(data, dict)
                        and "result" in data
                        and isinstance(data["result"], dict)
                        and "tools" in data["result"]
                    ):
                        tools = data["result"]["tools"]
                        if isinstance(tools, list):
                            filtered_tools = []
                            has_attack = False
                            for tool in tools:
                                tool_schema = {
                                    "name": tool.get("name", ""),
                                    "description": tool.get("description", "") or "",
                                    "inputSchema": tool.get("inputSchema", {})
                                    or tool.get("parameters", {})
                                    or {},
                                }

                                if registry.is_shadowing_attack(tool_schema):
                                    logger.warning(
                                        f"🚨 [Security Alert] Shadowing attack detected on tool '{tool.get('name')}'!"
                                    )
                                    has_attack = True
                                    if block_mode:
                                        # Block mode: Return a JSON-RPC error instead of the tool list
                                        error_resp = {
                                            "jsonrpc": "2.0",
                                            "error": {
                                                "code": -32000,
                                                "message": f"Access Denied: Unsafe shadow tool '{tool.get('name')}' blocked.",
                                            },
                                            "id": data.get("id"),
                                        }
                                        line_str = json.dumps(error_resp) + "\n"
                                        break
                                    continue
                                filtered_tools.append(tool)

                            if not (block_mode and has_attack):
                                data["result"]["tools"] = filtered_tools
                                line_str = json.dumps(data) + "\n"
                except Exception as ex:
                    logger.debug(f"JSON-RPC parse skip: {ex}")

            writer.write(line_str.encode("utf-8"))
            await writer.drain()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error piping subprocess stdout to main stdout: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def pipe_sub_stderr(reader: asyncio.StreamReader):
    """
    Pipes stderr from the subprocess directly to sys.stderr.
    """
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.flush()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error piping stderr: {e}")


async def run_proxy(
    cmd_args: List[str],
    baseline_path: str,
    threshold: float,
    block_mode: bool,
):
    # 1. Initialize Semantic Registry
    from mcp_vector_shield.mcp_registry import MCPSemanticRegistry

    registry = MCPSemanticRegistry(distance_threshold=threshold)

    # 2. Load and Register baseline tools
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, "r") as f:
                baselines = json.load(f)
            if isinstance(baselines, list):
                logger.info(f"Loading {len(baselines)} baseline tools from '{baseline_path}'...")
                for tool in baselines:
                    registry.register_baseline(tool)
            else:
                logger.error(f"Invalid baseline format in '{baseline_path}' (expected JSON list).")
        except Exception as e:
            logger.error(f"Failed to load baseline file '{baseline_path}': {e}")
    else:
        logger.warning(
            f"Baseline file '{baseline_path}' not found. Starting with empty baseline registry!"
        )

    # 3. Spawn Subprocess Command
    logger.info(f"Spawning target MCP server: {' '.join(cmd_args)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            cmd_args[0],
            *cmd_args[1:],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        logger.error(f"Failed to spawn target command: {e}")
        sys.exit(1)

    # 4. Connect Main Streams
    main_stdin_reader = await connect_stdin()
    main_stdout_writer = await connect_stdout()

    # 5. Run Concurrent Pipe Workers
    stdin_task = asyncio.create_task(pipe_stdin_to_sub(main_stdin_reader, proc.stdin))
    stdout_task = asyncio.create_task(
        pipe_sub_to_stdout(proc.stdout, main_stdout_writer, registry, block_mode)
    )
    stderr_task = asyncio.create_task(pipe_sub_stderr(proc.stderr))

    # Wait for the subprocess or the pipes to complete
    await proc.wait()

    # Cancel any active tasks
    for task in (stdin_task, stdout_task, stderr_task):
        if not task.done():
            task.cancel()

    logger.info(f"Target MCP server exited with code: {proc.returncode}")
    sys.exit(proc.returncode)


def main():
    parser = argparse.ArgumentParser(
        description="mcp-shield: Native stdio passthrough security proxy for Model Context Protocol (MCP)."
    )
    parser.add_argument(
        "--baseline",
        "-b",
        default="safe_baselines.json",
        help="Path to legitimate baseline tools JSON file (default: safe_baselines.json)",
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=0.05,
        help="Semantic L2 distance calibration threshold (default: 0.05)",
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Enable BLOCK mode (raise error response) instead of FILTER mode (strip tool).",
    )
    parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Target MCP server command to run as a subprocess (prefix with '--')",
    )

    args = parser.parse_args()

    # The command should start after a '--' token, which parses as trailing items in `cmd`
    target_cmd = args.cmd
    if target_cmd and target_cmd[0] == "--":
        target_cmd = target_cmd[1:]

    if not target_cmd:
        parser.print_help()
        print(
            "\nError: No target command specified. Provide a command to run after '--'.",
            file=sys.stderr,
        )
        print(
            "Example: mcp-shield -b safe_baselines.json -- npx -y @modelcontextprotocol/server-github",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        asyncio.run(
            run_proxy(
                cmd_args=target_cmd,
                baseline_path=args.baseline,
                threshold=args.threshold,
                block_mode=args.block,
            )
        )
    except KeyboardInterrupt:
        logger.info("mcp-shield proxy terminated by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
