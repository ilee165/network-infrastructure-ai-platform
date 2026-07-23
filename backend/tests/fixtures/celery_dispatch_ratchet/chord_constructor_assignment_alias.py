from celery import chord


def publish(header, body):
    publish_chord = chord
    publish_chord(header)(body)
