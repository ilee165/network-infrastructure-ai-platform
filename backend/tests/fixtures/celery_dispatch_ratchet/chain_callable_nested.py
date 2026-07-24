from celery import chain

workflow = chain(first.s(), second.s())  # noqa: F821
workflow()
