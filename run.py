import asyncio
import uvicorn
import os
import logging
from bot import run_bot
from server import app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_server():
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    logger.info("🚀 Starting ORION parcer (Server + Bot)...")
    await asyncio.gather(
        run_server(),
        run_bot(),
    )


if __name__ == "__main__":
    asyncio.run(main())
