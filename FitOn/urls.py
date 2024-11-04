"""
URL configuration for FitOn project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin

# from django.contrib.auth import views
from django.urls import path
from .views import signup, homepage, login, profile_view, upload_profile_picture
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("callback/", views.callback_google_fit, name="callback_google_fit"),
    path("authorize/", views.authorize_google_fit, name="authorize_google_fit"),
    path("", views.login, name="landing"),
    path("admin/", admin.site.urls),
    path("signup/", views.signup, name="signup"),
    path("home/", views.homepage, name="homepage"),
    path("login/", views.login, name="login"),
    path("accounts/login/", views.login, name="login"),
    path("deactivate/", views.deactivate_account, name="deactivate_account"),
    path(
        "deactivate/confirm/", views.confirm_deactivation, name="confirm_deactivation"
    ),
    path("logout/", views.login, name="logout"),
    path(
        "reset-password/", views.password_reset_request, name="password_reset_request"
    ),
    path(
        "reset-password/<str:uidb64>/<str:token>/",
        views.password_reset_confirm,
        name="password_reset_confirm",
    ),
    path("reset-password/done/", views.password_reset_done, name="password_reset_done"),
    path(
        "reset-password/complete/",
        views.password_reset_complete,
        name="password_reset_complete",
    ),
    path("profile/", views.profile_view, name="profile"),
    path(
        "upload_profile_picture/",
        views.upload_profile_picture_view,
        name="upload_profile_picture",
    ),
    path(
        "fitness_trainer_application_view/",
        views.fitness_trainer_application_view,
        name="fitness_trainer_application_view",
    ),
    path(
        "fitness_trainer_applications_list/",
        views.fitness_trainer_applications_list_view,
        name="fitness_trainer_applications_list",
    ),
    path("forum/", views.forum_view, name="forum"),
    path("forum/new/", views.new_thread_view, name="new_thread"),
    path("forum/<str:thread_id>/", views.thread_detail_view, name="thread_detail"),
    path("delete_post/", views.delete_post_view, name="delete_post"),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
