from celery import chord, signature


def build(task):
    header = [task.s("run-id"), task.si("immutable")]
    body = signature("discovery.continue_wave")
    return chord(header, body)
