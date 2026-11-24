import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("EG_BUILD_DIR", "work"))
