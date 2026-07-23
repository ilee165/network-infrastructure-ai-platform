from celery import chord as build_chord


def publish(header, body):
    pending = build_chord(
        header,
    )
    pending(body)
