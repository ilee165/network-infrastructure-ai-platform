from celery import signature


def publish():
    signature(
        "discovery.run",
        args=["run-id"],
    )()
