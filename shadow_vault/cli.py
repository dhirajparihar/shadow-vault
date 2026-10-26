"""
Command Line Interface (CLI) for ShadowVault:
- `mcp-proxy`: Transparent stdio gateway for any Model Context Protocol tool server.
- `serve`: Drop-in OpenAI-compatible reverse proxy server.
- `benchmark`: Run latency and throughput benchmarks.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.mcp_proxy import run_mcp_stdio_proxy


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="shadow-vault",
        description="The privacy layer for AI agent tool calls and Model Context Protocol (MCP).",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. mcp-proxy subcommand
    mcp_parser = subparsers.add_parser(
        "mcp-proxy",
        help="Transparent stdio gateway intercepting MCP tool calls.",
        description="Transparently intercepts JSON-RPC messages between an AI agent and downstream MCP tool server.",
    )
    mcp_parser.add_argument(
        "--session-id",
        type=str,
        default=os.environ.get("SHADOW_VAULT_SESSION_ID", "default"),
        help="Session identifier to scope token mappings.",
    )
    mcp_parser.add_argument(
        "--db-path",
        type=str,
        default=os.environ.get("SHADOW_VAULT_DB_PATH", ":memory:"),
        help="Path to SQLite vault file or ':memory:'.",
    )
    mcp_parser.add_argument(
        "--encryption-key",
        type=str,
        default=os.environ.get("SHADOW_VAULT_KEY"),
        help="Secret key for authenticated vault encryption at rest.",
    )
    mcp_parser.add_argument(
        "--fail-closed",
        action="store_true",
        default=os.environ.get("SHADOW_VAULT_FAIL_CLOSED", "").lower() in ("1", "true", "yes"),
        help="Enforce fail-closed privacy policy on unmapped tokens.",
    )
    mcp_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Downstream MCP server command to wrap (e.g. -- uvx mcp-server-sqlite).",
    )

    # 2. serve subcommand
    serve_parser = subparsers.add_parser(
        "serve",
        help="Launch drop-in OpenAI-compatible HTTP privacy proxy.",
    )
    serve_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind HTTP proxy server.",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind HTTP proxy server.",
    )
    serve_parser.add_argument(
        "--upstream",
        type=str,
        default=os.environ.get("SHADOW_VAULT_UPSTREAM_URL", "https://api.openai.com/v1"),
        help="Upstream LLM base URL.",
    )
    serve_parser.add_argument(
        "--db-path",
        type=str,
        default=os.environ.get("SHADOW_VAULT_DB_PATH", ":memory:"),
        help="Path to SQLite vault file.",
    )
    serve_parser.add_argument(
        "--encryption-key",
        type=str,
        default=os.environ.get("SHADOW_VAULT_KEY"),
        help="Secret key for authenticated vault encryption.",
    )
    serve_parser.add_argument(
        "--fail-closed",
        action="store_true",
        help="Enforce fail-closed privacy protection.",
    )

    # 3. benchmark subcommand
    subparsers.add_parser(
        "benchmark",
        help="Run reproducible latency, throughput, and streaming benchmarks.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "mcp-proxy":
        downstream = args.command
        # If command starts with '--', remove the separator
        if downstream and downstream[0] == "--":
            downstream = downstream[1:]

        if not downstream:
            sys.stderr.write(
                "Error: No downstream MCP command specified.\n"
                "Usage: shadow-vault mcp-proxy -- <mcp-server-command> [args...]\n"
                "Example: shadow-vault mcp-proxy -- python -m my_mcp_server\n"
            )
            return 1

        vault = ShadowVault(
            db_path=args.db_path,
            encryption_key=args.encryption_key,
            fail_closed=args.fail_closed,
        )
        return run_mcp_stdio_proxy(
            downstream_command=downstream,
            vault=vault,
            session_id=args.session_id,
        )

    elif args.subcommand == "serve":
        try:
            import uvicorn
            from shadow_vault.integrations.proxy_server import create_proxy_app
        except ImportError:
            sys.stderr.write(
                "Error: API server dependencies missing.\n"
                "Please run: pip install 'shadow-vault[api]'\n"
            )
            return 1

        vault = ShadowVault(
            db_path=args.db_path,
            encryption_key=args.encryption_key,
            fail_closed=args.fail_closed,
        )
        app = create_proxy_app(vault=vault, upstream_url=args.upstream)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    elif args.subcommand == "benchmark":
        import subprocess

        bench_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "benchmarks",
            "run_benchmarks.py",
        )
        if os.path.exists(bench_script):
            return subprocess.call([sys.executable, bench_script])
        else:
            sys.stderr.write(f"Benchmark script not found at: {bench_script}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
