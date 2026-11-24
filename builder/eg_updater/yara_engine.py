"""Server shim: rules are validated by every client (yara-x) before use."""
import os
from pathlib import Path

RULES_DIR = Path(os.environ.get("EG_BUILD_DIR", "work")) / "yara"


def available() -> bool:
    return False


def validate_source(text: str) -> None:
    return None
