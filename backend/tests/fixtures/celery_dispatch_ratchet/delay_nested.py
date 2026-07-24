import package


def publish() -> None:
    package.tasks.discovery.delay("run-id")
