import logging

import uvicorn

from app.api.routes import build_application
from app.config import get_settings
from app.utils.logging import configure_logging

LOGGER = logging.getLogger("zfcssh.startup")

settings = get_settings()
configure_logging(settings)
app = build_application(settings)
startup_check_complete = False


def run_startup_self_check() -> None:
    global startup_check_complete

    if startup_check_complete:
        return

    result = settings.ensure_startup_ready()
    for warning in result.warnings:
        LOGGER.warning("startup_warning warning=%s", warning)

    startup_check_complete = True


app.add_event_handler("startup", run_startup_self_check)


def main() -> None:
    run_startup_self_check()
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
