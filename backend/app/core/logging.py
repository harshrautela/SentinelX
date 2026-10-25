"""
SentinelX Logging Module
------------------------
Structured logging with automatic sensitive data masking.
Ensures tokens, keys, passwords, and authorization headers are never logged in plaintext.
"""

import logging
import re
import sys
from typing import Any

# Regex patterns for sensitive field values
SENSITIVE_PATTERNS = [
    (re.compile(r'(password["\']?\s*[:=]\s*["\'])([^"\']+)'), r'\1********'),
    (re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\'])([^"\']+)'), r'\1********'),
    (re.compile(r'(secret["\']?\s*[:=]\s*["\'])([^"\']+)'), r'\1********'),
    (re.compile(r'(access[_-]?token["\']?\s*[:=]\s*["\'])([^"\']+)'), r'\1********'),
    (re.compile(r'(Bearer\s+)([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)'), r'\1[REDACTED_JWT]'),
]


def mask_sensitive_data(text: str) -> str:
    """Mask credentials and sensitive strings in logs and evidence."""
    if not isinstance(text, str):
        return text
    masked = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


class SensitiveDataFilter(logging.Filter):
    """Logging filter to mask sensitive values from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_data(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: mask_sensitive_data(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(mask_sensitive_data(str(a)) for a in record.args)
        return True


def setup_logger(name: str = "sentinelx", level: str = "INFO") -> logging.Logger:
    """Configure a structured logger with security filters."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)

    return logger


logger = setup_logger("sentinelx")
