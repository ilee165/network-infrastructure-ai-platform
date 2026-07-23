from app.workers.tasks.discovery import run_discovery as publish


def trigger() -> None:
    publish("run-id")
