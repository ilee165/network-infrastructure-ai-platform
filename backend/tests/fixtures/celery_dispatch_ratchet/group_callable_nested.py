from celery import group

group(first.s(), second.s())()  # noqa: F821
