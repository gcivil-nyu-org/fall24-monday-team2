from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class PasswordResetRequest(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_request_time = models.DateTimeField(default=timezone.now)

    class Meta:
        app_label = "FitOn"

class Conversation(models.Model):
    users = models.ManyToManyField(User, related_name="conversations")
    created_at = models.DateTimeField(auto_now_add=True)

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, related_name="messages", on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name="sent_messages", on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)