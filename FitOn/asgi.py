"""
ASGI config for FitOn project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from django.urls import re_path

from FitOn import consumers

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "FitOn.settings")

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),  # Handles HTTP requests
        "websocket": AuthMiddlewareStack(
            URLRouter(
                [
                    re_path(
                        r"ws/chat/(?P<room_id>[a-zA-Z0-9_.-]+)/$",
                        consumers.ChatMessageConsumer.as_asgi(),
                    ),
                ]
            )
        ),
    }
)
