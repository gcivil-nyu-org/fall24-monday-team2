from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class PasswordResetRequest(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_request_time = models.DateTimeField(default=timezone.now)

    class Meta:
        app_label = "FitOn"


class GroupChatMember(models.Model):
    class AgreementStatus(models.TextChoices):
        IN_PROGRESS = "IN_PROGRESS"
        COMPLETED = "COMPLETED"
        CANCELED = "CANCELED"

    name = models.CharField("group name", max_length=200, default="")
    uid = models.CharField("userid", max_length=80)

    status = models.CharField(
        "status",
        max_length=20,
        choices=AgreementStatus.choices,
        default=AgreementStatus.IN_PROGRESS,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["name", "uid"], name="unique_group_chat_member"
            )
        ]
