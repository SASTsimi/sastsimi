"""The composition root: only configuration and safe logging construction."""

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from sastsimi.config.loader import ConfigError as ConfigError
from sastsimi.config.loader import load_config
from sastsimi.config.models import AppConfig
from sastsimi.logging import SafeJsonHandler, safe_event


def build_config(
    config_path: Path | None, overrides: Mapping[str, object]
) -> AppConfig:
    return load_config(config_path=config_path, cli=overrides)


def build_diagnostic_logger(stream: TextIO, level: str) -> logging.Logger:
    logger = logging.Logger("sastsimi", level=level)
    handler = SafeJsonHandler(stream)
    logger.addHandler(handler)
    return logger


# Public safe event factory for interface diagnostics.
diagnostic_event = safe_event
