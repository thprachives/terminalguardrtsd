import asyncio
import subprocess
import sys

async def run_process(cmd_args):
    proc = await asyncio.create_subprocess_exec(*cmd_args)
    await proc.wait()

async def main():
    # Change these paths if needed
    python_executable = sys.executable  # Current Python interpreter

    tasks = [
        run_process([python_executable, "test_email_server.py"]),
        run_process([python_executable, "mcp_middleware.py"]),
        run_process([python_executable, "dashboard_api.py"]),
    ]

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down services...")
