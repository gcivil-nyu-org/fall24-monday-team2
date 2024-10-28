from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class PasswordResetRequest(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_request_time = models.DateTimeField(default=timezone.now)

    class Meta:
        app_label = "FitOn"
