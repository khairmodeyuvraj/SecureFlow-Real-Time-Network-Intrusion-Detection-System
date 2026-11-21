import logging
import sys
from pathlib import Path


def get_logger(name: str = "SecureFlow-IDS", level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger with console and optional file handler."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(level)

        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        logger.addHandler(console_handler)

    return logger
