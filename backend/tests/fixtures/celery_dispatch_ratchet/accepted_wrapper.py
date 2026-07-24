from app.workers.dispatch import durable_dispatch


def publish() -> None:
    durable_dispatch(
        task_name="discovery.run",
        args=["run-id"],
        queue="discovery",
    )
