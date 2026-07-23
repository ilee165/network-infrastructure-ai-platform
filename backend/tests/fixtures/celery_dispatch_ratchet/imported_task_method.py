from app.workers.tasks import discovery as tasks


def trigger() -> None:
    tasks.run_discovery("run-id")
