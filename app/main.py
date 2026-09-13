"""WebGuard Pro entry point."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config.settings import AppConfig
from app.ui.app import WebGuardApp


def main():
    config = AppConfig()
    Path(config.db_path).parent.mkdir(parents=True, exist_ok=True)
    app = WebGuardApp(config)
    app.mainloop()


if __name__ == "__main__":
    main()
