from __future__ import annotations

from pathlib import Path

"""Canonical Arenyxa product identity.

The project intentionally exposes a single public/internal Arenyxa identity.  Windows 7
is a separately packaged runtime tier, not a second product namespace.
"""

APP_NAME = "Arenyxa"
APP_SLUG = "arenyxa"
PUBLISHER = "Arenyxa Contributors"
INTERNAL_PACKAGE = "arenyxa"

DATA_DIR_ENV = "ARENYXA_DATA_DIR"
RUNTIME_TIER_ENV = "ARENYXA_RUNTIME_TIER"
SOURCE_INTEGRITY_ENV = "ARENYXA_ENFORCE_SOURCE_INTEGRITY"
RELEASE_CHANNEL_ENV = "ARENYXA_RELEASE_CHANNEL"
RELEASE_SIGNING_KEY_ENV = "ARENYXA_RELEASE_SIGNING_KEY"

PROJECT_EXTENSION = ".arenyxa"
PROJECT_FORMAT = "arenyxa.project/1"
WORKFLOW_EXTENSION = ".arenyxa-workflow"

DATABASE_FILENAME = "arenyxa.db"
LOG_FILENAME = "arenyxa.jsonl"
EXECUTABLE_NAME = "Arenyxa.exe"

_ICON_DIR = Path(__file__).parent / "resources" / "icons"


def application_icon_png_path() -> Path:
    return _ICON_DIR / "arenyxa.png"


def application_icon_ico_path() -> Path:
    return _ICON_DIR / "arenyxa.ico"


def preferred_window_icon_path() -> Path:
    png = application_icon_png_path()
    return png if png.is_file() else application_icon_ico_path()

# Runtime-tier compatibility names are retained for internal Win7 feature policy only.
# They resolve to the canonical Arenyxa identity and do not expose a second namespace.
LEGACY_APP_NAME = APP_NAME
LEGACY_APP_SLUG = APP_SLUG
LEGACY_INTERNAL_PACKAGE = INTERNAL_PACKAGE
LEGACY_DATA_DIR_ENV = DATA_DIR_ENV
LEGACY_RUNTIME_TIER_ENV = RUNTIME_TIER_ENV
LEGACY_SOURCE_INTEGRITY_ENV = SOURCE_INTEGRITY_ENV
LEGACY_RELEASE_CHANNEL_ENV = RELEASE_CHANNEL_ENV
LEGACY_RELEASE_SIGNING_KEY_ENV = RELEASE_SIGNING_KEY_ENV
LEGACY_PROJECT_EXTENSIONS = (PROJECT_EXTENSION,)
LEGACY_PROJECT_FORMATS = (PROJECT_FORMAT,)
LEGACY_WORKFLOW_EXTENSIONS = (WORKFLOW_EXTENSION,)
LEGACY_DATABASE_FILENAME = DATABASE_FILENAME
LEGACY_LOG_FILENAME = LOG_FILENAME
LEGACY_EXECUTABLE_NAME = EXECUTABLE_NAME
