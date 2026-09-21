"""Application logging bootstrap, independent of database availability."""
import logging
import logging.config
import sys

from loguru import logger


class InterceptHandler(logging.Handler):
    """Forward standard logging to the configured Loguru sink."""

    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def setup_logging() -> None:
    logger.configure(handlers=[{
        "sink": sys.stdout,
        "level": "INFO",
        "format": "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} - {message}",
        "backtrace": False,
        "diagnose": False,
    }])
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {"gateway": {"()": InterceptHandler}},
        "root": {"level": "INFO", "handlers": ["gateway"]},
        "loggers": {
            "uvicorn": {"level": "WARNING", "handlers": [], "propagate": True},
            "sqlalchemy.engine": {"level": "WARNING", "handlers": [], "propagate": True},
        },
    })
