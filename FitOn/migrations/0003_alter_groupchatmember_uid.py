# Generated by Django 5.1.3 on 2024-12-09 19:50

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("FitOn", "0002_groupchatmember"),
    ]

    operations = [
        migrations.AlterField(
            model_name="groupchatmember",
            name="uid",
            field=models.IntegerField(default=0, verbose_name="user ID"),
        ),
    ]
