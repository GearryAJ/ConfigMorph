import os
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config


_runtime = tempfile.TemporaryDirectory(prefix="convert-in-tests-")
_root = Path(_runtime.name)
os.environ["FCS_DATA_DIR"] = str(_root / "data")
os.environ["FCS_WORKSPACE_DIR"] = str(_root / "workspace")


def pytest_sessionstart(session):
    command.upgrade(Config("alembic.ini"), "head")


def pytest_sessionfinish(session, exitstatus):
    from app.persistence.database import engine

    engine.dispose()
    _runtime.cleanup()