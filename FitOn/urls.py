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

<<<<<<< HEAD
from . import views
=======
from .views import (
    confirm_deactivation,
    deactivate_account,
    delete_post_view,
    fitness_trainer_application_view,
    fitness_trainer_applications_list_view,
    forum_view,
    homepage,
    login,
    new_thread_view,
    password_reset_complete,
    password_reset_confirm,
    password_reset_done,
    password_reset_request,
    profile_view,
    signup,
    thread_detail_view,
    upload_profile_picture_view,
)
>>>>>>> 5e20de8 (update password testing)
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin

# from django.contrib.auth import views
from django.urls import path
from .views import signup, homepage, login, profile_view, upload_profile_picture
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
<<<<<<< HEAD
    path("callback/", views.callback_google_fit, name="callback_google_fit"),
    path("authorize/", views.authorize_google_fit, name="authorize_google_fit"),
    path("", views.login, name="landing"),
    path("admin/", admin.site.urls),
    path("signup/", views.signup, name="signup"),
    path("home/", views.homepage, name="homepage"),
    path("login/", views.login, name="login"),
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
=======
    path("", login, name="landing"),
    path("admin/", admin.site.urls),
    path("signup/", signup, name="signup"),
    path("home/", homepage, name="homepage"),
    path("login/", login, name="login"),
    path("deactivate/", deactivate_account, name="deactivate_account"),
    path("deactivate/confirm/", confirm_deactivation, name="confirm_deactivation"),
    path("logout/", login, name="logout"),
    path("reset-password/", password_reset_request, name="password_reset_request"),
    path(
        "reset-password/<str:user_id>/<str:token>/",
        password_reset_confirm,
        name="password_reset_confirm",
    ),
    path("reset-password/done/", password_reset_done, name="password_reset_done"),
    path(
        "reset-password/complete/",
        password_reset_complete,
        name="password_reset_complete",
    ),
    path("profile/", profile_view, name="profile"),
    path(
        "upload_profile_picture/",
        upload_profile_picture_view,
>>>>>>> 5e20de8 (update password testing)
        name="upload_profile_picture",
    ),
    path(
        "fitness_trainer_application_view/",
<<<<<<< HEAD
        views.fitness_trainer_application_view,
=======
        fitness_trainer_application_view,
>>>>>>> 5e20de8 (update password testing)
        name="fitness_trainer_application_view",
    ),
    path(
        "fitness_trainer_applications_list/",
<<<<<<< HEAD
        views.fitness_trainer_applications_list_view,
        name="fitness_trainer_applications_list",
    ),
    path("forum/", views.forum_view, name="forum"),
    path("forum/new/", views.new_thread_view, name="new_thread"),
    path("forum/<str:thread_id>/", views.thread_detail_view, name="thread_detail"),
    path("delete_post/", views.delete_post_view, name="delete_post"),
=======
        fitness_trainer_applications_list_view,
        name="fitness_trainer_applications_list",
    ),
    path("forum/", forum_view, name="forum"),
    path("forum/new/", new_thread_view, name="new_thread"),
    path("forum/<str:thread_id>/", thread_detail_view, name="thread_detail"),
    path("delete_post/", delete_post_view, name="delete_post"),
>>>>>>> 5e20de8 (update password testing)
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
