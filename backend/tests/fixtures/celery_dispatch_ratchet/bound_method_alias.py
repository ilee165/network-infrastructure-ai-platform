from app.workers.celery_app import celery_app


def publish() -> None:
    publish_task = celery_app.send_task
    publish_task("discovery.run", args=["run-id"], queue="discovery")
