from app.workers.celery_app import celery_app


@celery_app.task
def bare_task() -> None:
    pass
