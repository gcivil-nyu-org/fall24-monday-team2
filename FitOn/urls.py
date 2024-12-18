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


app_name = "FitOn"

urlpatterns = [
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
    path("logout/", views.custom_logout, name="logout"),
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
    path(
        "fitness_trainers_list/",
        views.fitness_trainers_list_view,
        name="fitness_trainers_list",
    ),
    path(
        "trainer/standard-users/",
        views.standard_users_list_view,
        name="standard_users_list",
    ),
    path(
        "trainer/send-data-request/", views.send_data_request, name="send_data_request"
    ),
    path(
        "trainer/cancel-data-request/",
        views.cancel_data_request,
        name="cancel_data_request",
    ),
    path(
        "trainer/view_user_data/async/<str:user_id>/data/",
        views.async_view_user_data,
        name="async_view_user_data",
    ),
    path(
        "trainer/view_user_data/<str:user_id>/data/",
        views.view_user_data,
        name="view_user_data",
    ),
    path(
        "trainer/create_custom_plan/<str:user_id>/",
        views.create_custom_plan,
        name="create_custom_plan",
    ),
    path(
        "user/view_custom_plan/<str:trainer_id>/",
        views.view_custom_plan,
        name="view_custom_plan",
    ),
    path(
        "user/request_custom_plan/",
        views.request_custom_plan,
        name="request_custom_plan",
    ),
    path("user/accept_trainer/", views.accept_trainer, name="accept_trainer"),
    path("user/deny_trainer/", views.deny_trainer, name="deny_trainer"),
    path(
        "user/provide_access_to_trainer/",
        views.provide_access_to_trainer,
        name="provide_access_to_trainer",
    ),
    path(
        "user/revoke_access_to_trainer/",
        views.revoke_access_to_trainer,
        name="revoke_access_to_trainer",
    ),
    path(
        "approve_fitness_trainer/",
        views.approve_fitness_trainer,
        name="approve_fitness_trainer",
    ),
    path(
        "reject_fitness_trainer/",
        views.reject_fitness_trainer,
        name="reject_fitness_trainer",
    ),
    path("forum/", views.forum_view, name="forum"),
    path("forum/new/", views.new_thread_view, name="new_thread"),
    path("forum/<str:thread_id>/", views.thread_detail_view, name="thread_detail"),
    path("forum/section/<str:section_name>/", views.section_view, name="forum_section"),
    path("delete_post/", views.delete_post_view, name="delete_post"),
    path("metrics/", views.list_metrics, name="metrics_list"),
    path("workouts/", views.list_exercises, name="list_exercises"),
    path("data/", views.get_metric_data, name="get_metric_data"),
    path("store/", views.store_exercises, name="store_exercises"),
    path("submit-health-data/", views.health_data_view, name="submit_health_data"),
    path("delink/", views.delink_google_fit, name="delink_google_fit"),
    path("ban_user/", views.toggle_ban_user, name="toggle_ban_user"),
    path("mute_user/", views.toggle_mute_user, name="toggle_mute_user"),
    path("punishments/", views.punishments_view, name="punishments"),
    path("unban_user/", views.unban_user, name="unban_user"),
    path("unmute_user/", views.unmute_user, name="unmute_user"),
    path("add_reply/", views.add_reply, name="add_reply"),
    path("delete_reply/", views.delete_reply_view, name="delete_reply"),
    path("delete_thread/", views.delete_thread, name="delete_thread"),
    path("reports/", views.reports_view, name="reports"),
    path("chat/", views.private_chat, name="chat"),
    path("chatg/", views.group_chat, name="group_chat"),
    path(
        "chat/history/<str:room_id>/", views.get_chat_history, name="get_chat_history"
    ),
    path("chat/group/create/", views.create_group_chat, name="create_group_chat"),
    path("chat/group/invite/", views.invite_to_group, name="invite_to_group"),
    path("chat/group/join/", views.join_group_chat, name="join_group_chat"),
    path("chat/group/leave/", views.leave_group_chat, name="leave_group_chat"),
    # path("chat/group/check/", views.get_pending_invitations),
    path("chat/search_users/", views.search_users, name="search_users"),
    # path(
    #     "pending_invitations/",
    #     views.get_pending_invitations,
    #     name="pending_invitations",
    # ),
    path("warn_action/", views.warn_action, name="warn_action"),
    path("dismiss_warning/", views.dismiss_warning, name="dismiss_warning"),
    path(
        "chat/group/members/<str:group_name>/",
        views.get_group_members,
        name="get_group_members",
    ),
    path("fitness-goals/", views.fitness_goals_view, name="fitness_goals"),
    path("fitness-goals/edit/", views.edit_goal, name="edit_goal"),
    path("fitness-goals/delete/", views.delete_goal, name="delete_goal"),
    path("chat/group/add_users/", views.add_users_to_group, name="add_users_to_group"),
    path(
        "chat/mark_messages_as_read/<str:room_id>/",
        views.mark_messages_as_read,
        name="mark_messages_as_read",
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
