from app.services.discovery import trigger_discovery_run as trigger


def run() -> None:
    trigger("run-id")
