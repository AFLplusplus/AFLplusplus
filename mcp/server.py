"""AFL++ MCP Server - Main server class with stdio/SSE/HTTP transport support."""

import asyncio
import json
import sys
from typing import Any, Dict, Optional
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.server.sse import SseServerTransport
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    # Fallback stubs for when mcp package not installed
    class Server:
        def __init__(self, name: str):
            self.name = name
        def tool(self, name: str, description: str = ""):
            def decorator(func):
                return func
            return decorator
    def stdio_server():
        raise RuntimeError("mcp package not installed")
    class SseServerTransport:
        def __init__(self, *args, **kwargs):
            pass

from . import tools


class AFLPPMCPServer:
    """AFL++ MCP Server wrapper.

    Provides access to AFL++ fuzzing data through the Model Context Protocol.
    Supports stdio, SSE, and HTTP transports.
    """

    def __init__(self, name: str = "aflpp-mcp-server"):
        self.name = name
        if MCP_AVAILABLE:
            self.server = Server(name)
            self._register_tools()
        else:
            self.server = None

    def _register_tools(self):
        """Register all AFL++ tools with the MCP server."""
        if not self.server:
            return

        @self.server.tool(
            name="get_stats",
            description="Get current fuzzing statistics from fuzzer_stats file"
        )
        async def get_stats_tool(output_dir: Optional[str] = None) -> str:
            try:
                result = tools.get_stats(output_dir)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="list_queue",
            description="List test cases in the queue directory"
        )
        async def list_queue_tool(
            output_dir: Optional[str] = None,
            limit: int = 100,
            offset: int = 0
        ) -> str:
            try:
                result = tools.list_queue(output_dir, limit, offset)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="analyze_queue",
            description="Analyze queue characteristics and size distribution"
        )
        async def analyze_queue_tool(output_dir: Optional[str] = None) -> str:
            try:
                result = tools.analyze_queue(output_dir)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="list_crashes",
            description="List crash samples in the crashes directory"
        )
        async def list_crashes_tool(
            output_dir: Optional[str] = None,
            limit: int = 100,
            offset: int = 0
        ) -> str:
            try:
                result = tools.list_crashes(output_dir, limit, offset)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="analyze_crash",
            description="Analyze a single crash sample"
        )
        async def analyze_crash_tool(
            crash_path: str,
            target_binary: Optional[str] = None
        ) -> str:
            try:
                result = tools.analyze_crash(crash_path, target_binary)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="minimize_crash",
            description="Minimize a crash sample using afl-tmin"
        )
        async def minimize_crash_tool(
            crash_path: str,
            output_dir: Optional[str] = None,
            target_binary: Optional[str] = None
        ) -> str:
            try:
                result = tools.minimize_crash(crash_path, output_dir, target_binary)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="get_coverage",
            description="Get coverage information from fuzzer_stats"
        )
        async def get_coverage_tool(output_dir: Optional[str] = None) -> str:
            try:
                result = tools.get_coverage(output_dir)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

        @self.server.tool(
            name="recommend_strategy",
            description="Recommend fuzzing strategies based on current statistics"
        )
        async def recommend_strategy_tool(output_dir: Optional[str] = None) -> str:
            try:
                result = tools.recommend_strategy(output_dir)
                return json.dumps(result, indent=2)
            except Exception as e:
                return json.dumps({"error": str(e)})

    async def run_stdio(self):
        """Run the server using stdio transport."""
        if not MCP_AVAILABLE:
            raise RuntimeError("mcp package not installed. Install with: pip install mcp")

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )

    async def run_sse(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the server using SSE transport over HTTP."""
        if not MCP_AVAILABLE:
            raise RuntimeError("mcp package not installed. Install with: pip install mcp")

        try:
            from starlette.applications import Starlette
            from starlette.routing import Route
            import uvicorn
        except ImportError:
            raise RuntimeError(
                "starlette and uvicorn required for SSE transport. "
                "Install with: pip install starlette uvicorn"
            )

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.server.run(
                    streams[0],
                    streams[1],
                    self.server.create_initialization_options()
                )

        async def handle_messages(request):
            await sse.handle_post_message(
                request.scope, request.receive, request._send
            )

        app = Starlette(
            routes=[
                Route("/sse", endpoint=handle_sse),
                Route("/messages/", endpoint=handle_messages, methods=["POST"]),
            ]
        )

        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

    async def run_http(self, host: str = "0.0.0.0", port: int = 8000):
        """Alias for run_sse - HTTP transport uses SSE under the hood."""
        await self.run_sse(host, port)


def main():
    """Main entry point for running the AFL++ MCP server."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AFL++ MCP Server - Model Context Protocol server for AFL++"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport type (default: stdio)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for SSE/HTTP transport (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE/HTTP transport (default: 8000)"
    )

    args = parser.parse_args()

    server = AFLPPMCPServer()

    if args.transport == "stdio":
        asyncio.run(server.run_stdio())
    elif args.transport in ["sse", "http"]:
        asyncio.run(server.run_sse(args.host, args.port))


if __name__ == "__main__":
    main()
