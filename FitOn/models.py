from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class PasswordResetRequest(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_request_time = models.DateTimeField(default=timezone.now)

    class Meta:
        app_label = "FitOn"


class Choices:
    force = [("push", "Push"), ("pull", "Pull"), ("static", "Static")]

    level = [
        ("beginner", "Beginner"),
        ("intermediate", "Intermediate"),
        ("expert", "Expert"),
    ]

    mechanic = [
        ("compound", "Compound"),
        ("isolation", "Isolation"),
    ]

    equipment = [
        ("body only", "Body Only"),
        ("machine", "Machine"),
        ("kettlebells", "Kettlebells"),
        ("dumbbell", "Dumbbell"),
        ("cable", "Cable"),
        ("barbell", "Barbell"),
        ("bands", "Bands"),
        ("medicine ball", "Medicine Ball"),
        ("exercise ball", "Exercise Ball"),
        ("e-z curl bar", "E-Z Curl Bar"),
        ("foam roll", "Foam Roll"),
    ]

    category = [
        ("strength", "Strength"),
        ("stretching", "Stretching"),
        ("plyometrics", "Plyometrics"),
        ("strongman", "Strongman"),
        ("powerlifting", "Powerlifting"),
        ("cardio", "Cardio"),
        ("olympic weightlifting", "Olympic Weightlifting"),
        ("crossfit", "Crossfit"),
        ("weighted bodyweight", "Weighted Bodyweight"),
        ("assisted bodyweight", "Assisted Bodyweight"),
    ]


class MuscleGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)


class Exercise(models.Model):
    name = models.CharField(max_length=100)
    force = models.CharField(max_length=100, choices=Choices.force, null=True)
    level = models.CharField(max_length=100, choices=Choices.level)
    mechanic = models.CharField(max_length=100, choices=Choices.mechanic, null=True)
    equipment = models.CharField(max_length=100, choices=Choices.equipment, null=True)
    primaryMuscles = models.ManyToManyField(
        MuscleGroup, blank=True, related_name="primary_muscles"
    )
    secondaryMuscles = models.ManyToManyField(
        MuscleGroup, blank=True, related_name="secondary_muscles"
    )
    instructions = models.CharField(max_length=10000, blank=True, null=True)
    category = models.CharField(max_length=100, choices=Choices.category)


class Choices:
    sex = [
        ("male", "Male"),
        ("female", "Female"),
        ("other", "Other"),
    ]


class User(models.Model):
    name = models.CharField(max_length=100, default="Default Name")
    email = models.EmailField(default="example@example.com", unique=True)
    phone = models.CharField(max_length=15, default="000-000-0000")
    sex = models.CharField(max_length=10, choices=Choices.sex, default="other")
    height = models.FloatField(max_length=100)
    weight = models.FloatField(max_length=100)
    city = models.CharField(max_length=50)
    avatar = models.ImageField(
        upload_to="avatars/",
        default="avatars/default-avatar.png",
        null=True,
        blank=True,
    )

    def __str__(self):
        return self.name + " (" + self.email + ")"


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
