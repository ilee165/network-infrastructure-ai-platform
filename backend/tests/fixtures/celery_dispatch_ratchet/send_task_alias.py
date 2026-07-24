from app.workers.celery_app import celery_app as publisher


def publish() -> None:
    publisher.send_task(
        "discovery.run",
        args=["run-id"],
        queue="discovery",
    )
