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
from .views import (
    confirm_deactivation,
    deactivate_account,
    fitness_trainer_application_view,
    fitness_trainer_applications_list_view,
    homepage,
    login,
    password_reset_complete,
    password_reset_confirm,
    password_reset_done,
    password_reset_request,
    profile_view,
    signup,
    upload_profile_picture_view,
)
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path

urlpatterns = [
    path('', login, name='landing'),
    path('admin/', admin.site.urls),
    path('signup/', signup, name='signup'),
    path('home/', homepage, name='homepage'),
    path('login/', login, name='login'),
    path('deactivate/', deactivate_account, name='deactivate_account'),
    path('deactivate/confirm/', confirm_deactivation, name='confirm_deactivation'),
    path('logout/', login, name='logout'),
    path('reset-password/', password_reset_request, name='password_reset_request'),
    path('reset-password/<str:user_id>/<str:token>/', password_reset_confirm, name='password_reset_confirm'),
    path('reset-password/done/', password_reset_done, name='password_reset_done'),
    path('reset-password/complete/', password_reset_complete, name='password_reset_complete'),
    path('profile/', profile_view, name='profile'),
    path('upload_profile_picture/', upload_profile_picture_view, name='upload_profile_picture'),
    path('fitness_trainer_application_view/', fitness_trainer_application_view, name='fitness_trainer_application_view'),
    path('fitness_trainer_applications_list/', fitness_trainer_applications_list_view, name='fitness_trainer_applications_list'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    

