import package


class Publisher:
    def publish(self) -> None:
        package.tasks.discovery.apply_async(args=["run-id"])
