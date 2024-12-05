from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.serializers import serialize
from .models import Exercise, MuscleGroup, User
from django.http import JsonResponse

from .dynamodb import (
    add_fitness_trainer_application,
    # create_post,
    post_comment,
    create_thread,
    create_reply,
    create_user,
    delete_user_by_username,
    delete_post,
    fetch_posts_for_thread,
    get_fitness_trainer_applications,
    get_last_reset_request_time,
    get_user,
    get_user_by_email,
    get_user_by_uid,
    get_user_by_username,
    update_reset_request_time,
    update_user,
    update_user_password,
    upload_profile_picture,
    fetch_filtered_threads,
    fetch_all_users,
    get_fitness_data,
    dynamodb,
    threads_table,
    get_fitness_trainers,
    make_fitness_trainer,
    remove_fitness_trainer,
    delete_reply,
    fetch_reported_threads_and_comments,
    mark_thread_as_reported,
    mark_comment_as_reported,
    posts_table,
    delete_thread_by_id,
    get_section_stats,
    get_users_without_specific_username,
    get_chat_history_from_db,
    chat_table,
    get_standard_users,
    send_data_request_to_user,
    add_to_list,
    remove_from_list,
    cancel_data_request_to_user,
    get_mock_user_by_uid,
    mark_user_as_warned_thread,
    mark_user_as_warned_comment,
    set_user_warned_to_false,
)
from .rds import rds_main, fetch_user_data

from .forms import (
    FitnessTrainerApplicationForm,
    LoginForm,
    PasswordResetForm,
    ProfileForm,
    SetNewPasswordForm,
    SignUpForm,
)

from .models import GroupChatMember

# from .models import PasswordResetRequest
import datetime as dt
import re
import ast
from datetime import datetime
import pytz
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
import pandas as pd

# from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout
from django.contrib import messages
from django.conf import settings

# from django.core.files.storage import FileSystemStorage
from django.core.mail import EmailMessage

# from django.core.mail.backends.locmem import EmailBackend
# from django.core.mail import EmailMultiAlternatives
from django.http import JsonResponse, HttpResponseForbidden
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

# from django.utils.encoding import force_bytes
# from django.utils.html import strip_tags
# from django.utils.http import urlsafe_base64_encode
# import os
from asgiref.sync import sync_to_async
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
import uuid
import boto3
import pymysql
from google_auth_oauthlib.flow import Flow
import requests

# from django.contrib.auth.decorators import login_required
import json

# from google import Things
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import asyncio
from collections import defaultdict
from boto3.dynamodb.conditions import Key, Attr

# Define metric data types
dataTypes = {
    "heart_rate": "com.google.heart_rate.bpm",
    "resting_heart_rate": "com.google.heart_rate.bpm",
    "steps": "com.google.step_count.delta",
    "sleep": "com.google.sleep.segment",
    "oxygen": "com.google.oxygen_saturation",
    "activity": "com.google.activity.segment",
    "glucose": "com.google.blood_glucose",
    "pressure": "com.google.blood_pressure",
}

df = pd.read_csv("google_fit_activity_types.csv")

SCOPES = [
    "https://www.googleapis.com/auth/fitness.activity.read",
    "https://www.googleapis.com/auth/fitness.body.read",
    "https://www.googleapis.com/auth/fitness.heart_rate.read",
    "https://www.googleapis.com/auth/fitness.sleep.read",
    "https://www.googleapis.com/auth/fitness.blood_glucose.read",
    "https://www.googleapis.com/auth/fitness.blood_pressure.read",
    "https://www.googleapis.com/auth/fitness.body_temperature.read",
    "https://www.googleapis.com/auth/fitness.location.read",
    "https://www.googleapis.com/auth/fitness.nutrition.read",
    "https://www.googleapis.com/auth/fitness.oxygen_saturation.read",
    "https://www.googleapis.com/auth/fitness.reproductive_health.read",
]


def homepage(request):
    username = request.session.get("username", "Guest")
    user_id = request.session.get("user_id")  # Retrieve user_id from session

    if not user_id:
        return redirect("login")  # Redirect to login if the user is not authenticated

    # Fetch user details from DynamoDB
    user = get_user(user_id)  # Replace with your function to fetch the user
    is_warned = user.get("is_warned", False)  # Get the 'is_warned' status

    return render(request, "home.html", {"username": username, "is_warned": is_warned})


def list_metrics(request):
    return render(request, "metric_list.html")


@sync_to_async
def add_message(request, level, message):
    messages.add_message(request, level, message)


@sync_to_async
def perform_redirect(url_name):
    return redirect(url_name)


def login(request):
    error_message = None

    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            # Query DynamoDB for the user by username
            user = get_user_by_username(username)

            if user:
                # Get the hashed password from DynamoDB
                stored_password = user["password"]
                user_id = user["user_id"]

                # Verify the password using Django's check_password
                if check_password(password, stored_password):
                    # Set the session and redirect to the homepage
                    request.session["username"] = username
                    request.session["user_id"] = user_id
                    return redirect("homepage")
                else:
                    error_message = "Invalid password. Please try again."
            else:
                error_message = "User does not exist."

    else:
        form = LoginForm()

    return render(request, "login.html", {"form": form, "error_message": error_message})


def custom_logout(request):
    # Log out the user
    logout(request)

    # Clear the entire session to ensure no data is persisted
    request.session.flush()

    # Redirect to the homepage or a specific page after logging out
    response = redirect("login")
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"  # HTTP 1.1
    response["Pragma"] = "no-cache"  # HTTP 1.0
    response["Expires"] = "0"  # Proxies
    return response


def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            email = form.cleaned_data["email"]
            name = form.cleaned_data["name"]
            date_of_birth = form.cleaned_data["date_of_birth"]
            gender = form.cleaned_data["gender"]
            password = form.cleaned_data["password"]
            height = form.cleaned_data["height"]
            weight = form.cleaned_data["weight"]

            # Hash the password before saving it
            hashed_password = make_password(password)

            # Create a unique user ID
            user_id = str(uuid.uuid4())

            # Sync data with DynamoDB
            if create_user(
                user_id,
                username,
                email,
                name,
                date_of_birth,
                gender,
                height,
                weight,
                hashed_password,
            ):
                request.session["username"] = username
                request.session["user_id"] = user_id
                return redirect("homepage")
            else:
                form.add_error(None, "Error creating user in DynamoDB.")
    else:
        form = SignUpForm()  # Return an empty form for the GET request

    return render(
        request, "signup.html", {"form": form}
    )  # Ensure form is passed for both GET and POST


def password_reset_request(request):
    countdown = None
    error_message = None
    form = PasswordResetForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"]
        if not email:
            error_message = "The email you entered is not registered with an account."
            return render(
                request,
                "password_reset_request.html",
                {"form": form, "error_message": error_message},
            )
        user = get_user_by_email(email)
        if user:
            if not user.is_active:
                error_message = (
                    "The email you entered is not registered with an account."
                )
                return render(
                    request,
                    "password_reset_request.html",
                    {"form": form, "error_message": error_message},
                )
            last_request_time_str = get_last_reset_request_time(user.user_id)
            if last_request_time_str:
                last_request_time = timezone.datetime.fromisoformat(
                    last_request_time_str
                )
                time_since_last_request = timezone.now() - last_request_time
                if time_since_last_request < timedelta(minutes=1):
                    countdown = 60 - time_since_last_request.seconds
                    return render(
                        request,
                        "password_reset_request.html",
                        {"form": form, "countdown": countdown},
                    )
            update_reset_request_time(user.user_id)
            reset_token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.user_id))
            reset_url = request.build_absolute_uri(
                reverse("password_reset_confirm", args=[uid, reset_token])
            )
            message = render_to_string(
                "password_reset_email.html",
                {"username": user.username, "reset_url": reset_url},
            )
            email_message = EmailMessage(
                "Password Reset Requested",
                message,
                "fiton.notifications@gmail.com",
                [email],
            )
            email_message.content_subtype = "html"
            email_message.send()
            return redirect("password_reset_done")
        error_message = "The email you entered is not registered with an account."
        return render(
            request,
            "password_reset_request.html",
            {"form": form, "error_message": error_message},
        )
    return render(
        request,
        "password_reset_request.html",
        {"form": form, "error_message": error_message, "countdown": countdown},
    )


def password_reset_confirm(request, uidb64, token):
    if not uidb64 or not token:
        return render(
            request,
            "password_reset_invalid.html",
            {"error_message": "The password reset link is invalid or has expired."},
        )
    try:
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = get_mock_user_by_uid(user_id)
        if user and default_token_generator.check_token(user, token):
            form = SetNewPasswordForm(request.POST or None)
            if request.method == "POST" and form.is_valid():
                new_password = form.cleaned_data["new_password"]
                confirm_password = form.cleaned_data["confirm_password"]
                if new_password == confirm_password:
                    update_user_password(user.user_id, new_password)
                    messages.success(
                        request, "Your password has been successfully reset."
                    )
                    return redirect("password_reset_complete")
                form.add_error("confirm_password", "Passwords do not match.")
            return render(request, "password_reset_confirm.html", {"form": form})
        return render(
            request,
            "password_reset_invalid.html",
            {"error_message": "The password reset link is invalid or has expired."},
        )
    except Exception:
        return render(
            request,
            "password_reset_invalid.html",
            {"error_message": "The password reset link is invalid or has expired."},
        )


def password_reset_complete(request):
    return render(request, "password_reset_complete.html")


def password_reset_done(request):
    return render(request, "password_reset_done.html")


def upload_profile_picture_view(request):
    user_id = request.session.get("user_id")  # Get the user ID from the session

    if request.method == "POST" and request.FILES.get("profile_picture"):
        profile_picture = request.FILES["profile_picture"]

        # Upload to S3 and get the URL
        new_image_url = upload_profile_picture(user_id, profile_picture)

        if new_image_url:
            return JsonResponse({"success": True, "new_image_url": new_image_url})
        else:
            return JsonResponse(
                {"success": False, "message": "Failed to upload image to S3"}
            )

    return JsonResponse({"success": False, "message": "No file uploaded"})


def profile_view(request):
    user_id = request.session.get("user_id")

    # Fetch user details from DynamoDB
    user = get_user(user_id)

    if not user:
        messages.error(request, "User not found.")
        return redirect("login")

    if request.method == "POST":
        # Handle profile picture upload
        if "profile_picture" in request.FILES:
            profile_picture = request.FILES["profile_picture"]
            image_url = upload_profile_picture(user_id, profile_picture)

            if image_url:
                # Update the user's profile picture URL in DynamoDB
                update_user(user_id, {"profile_picture": {"Value": image_url}})
                messages.success(request, "Profile picture updated successfully!")
                return redirect("profile")
            else:
                messages.error(request, "Failed to upload profile picture.")

        # Handling other profile updates
        form = ProfileForm(request.POST)
        if form.is_valid():
            # Prepare data to be updated
            update_data = {
                "name": {"Value": form.cleaned_data["name"]},
                "date_of_birth": {"Value": form.cleaned_data["date_of_birth"]},
                "gender": {"Value": form.cleaned_data["gender"]},
                "height": {"Value": form.cleaned_data["height"]},
                "weight": {"Value": form.cleaned_data["weight"]},
                "bio": {"Value": form.cleaned_data["bio"]},
                "address": {"Value": form.cleaned_data["address"]},
            }

            # Only add phone number and country code if provided
            country_code = form.cleaned_data["country_code"]
            phone_number = form.cleaned_data["phone_number"]

            if country_code:  # If country code is provided, add it to update_data
                update_data["country_code"] = {"Value": country_code}
            if phone_number:  # If phone number is provided, add it to update_data
                update_data["phone_number"] = {"Value": phone_number}

            update_user(user_id, update_data)
            messages.success(request, "Profile updated successfully!")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below")
    else:
        form = ProfileForm(
            initial={
                "name": user.get("name", ""),
                "date_of_birth": user.get("date_of_birth", ""),
                "email": user.get("email", ""),
                "gender": user.get("gender", ""),
                "phone_number": user.get("phone_number", ""),
                "height": user.get("height", ""),
                "weight": user.get("weight", ""),
                "address": user.get("address", ""),
                "bio": user.get("bio", ""),
                "country_code": user.get("country_code", ""),  # Default country code
            }
        )

    return render(request, "profile.html", {"form": form, "user": user})


def deactivate_account(request):
    # This simply shows the confirmation page
    return render(request, "deactivate.html")


def confirm_deactivation(request):
    if request.method == "POST":
        username = request.session.get("username")

        if username:
            # Delete the user from DynamoDB
            if delete_user_by_username(username):
                # Log the user out and redirect to the homepage
                logout(request)
                request.session.flush()
                return redirect("homepage")  # Redirect to homepage after deactivation
            else:
                return render(
                    request,
                    "deactivate.html",
                    {"error_message": "Error deleting the account."},
                )
        else:
            # Redirect to login if there's no username in session
            return redirect("login")
    else:
        # Redirect to the deactivate page if the request method is not POST
        return redirect("deactivate_account")


def authorize_google_fit(request):
    credentials = request.session.get("google_fit_credentials")
    # print("inside auth")

    if not credentials or credentials.expired:
        # if settings.DEBUG == True:
        #     flow = Flow.from_client_secrets_file('credentials.json', SCOPES)
        # else:
        # print(settings.GOOGLEFIT_CLIENT_CONFIG)
        flow = Flow.from_client_config(settings.GOOGLEFIT_CLIENT_CONFIG, SCOPES)
        flow.redirect_uri = request.build_absolute_uri(
            reverse("callback_google_fit")
        ).replace("http://", "https://")
        # print("Redirected URI: ", flow.redirect_uri)
        authorization_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true"
        )
        # Debugging print statements
        # print("Authorization URL:", authorization_url)
        # print("State:", state)

        request.session["google_fit_state"] = state
        return redirect(authorization_url)
    return redirect("profile")


def callback_google_fit(request):
    user_id = request.session.get("user_id")
    # print("Inside Callback")
    # print("Session: ")
    # Fetch user details from DynamoDB
    user = get_user(user_id)
    state = request.session.get("google_fit_state")
    if state:
        # if settings.DEBUG:
        #     flow = Flow.from_client_secrets_file('credentials.json', SCOPES, state=state)
        # else:
        # print("inside calback")

        flow = Flow.from_client_config(
            settings.GOOGLEFIT_CLIENT_CONFIG, SCOPES, state=state
        )
        # print("flow=", flow)
        flow.redirect_uri = request.build_absolute_uri(reverse("callback_google_fit"))
        flow.fetch_token(authorization_response=request.build_absolute_uri())

        credentials = flow.credentials
        request.session["credentials"] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
        }

        form = ProfileForm(
            initial={
                "name": user.get("name", ""),
                "date_of_birth": user.get("date_of_birth", ""),
                "email": user.get("email", ""),
                "gender": user.get("gender", ""),
                "phone_number": user.get("phone_number", ""),
                "address": user.get("address", ""),
                "bio": user.get("bio", ""),
                "country_code": user.get("country_code", ""),  # Default country code
            }
        )

        # Set a success message
        messages.success(request, "Signed in Successfully")

        # Set login_success to True for successful login
        login_success = True
        return render(
            request,
            "profile.html",
            {"login_success": login_success, "form": form, "user": user},
        )

    # In case of failure or missing state, redirect to a fallback page or profile without login_success
    # Handle invalid state
    messages.error(request, "Sign-in failed. Please try again.")
    return redirect("homepage")


def delink_google_fit(request):
    if "credentials" in request.session:
        credentials = Credentials(**request.session["credentials"])

        # Revoke the token on Google's side (optional but recommended)
        revoke_endpoint = "https://accounts.google.com/o/oauth2/revoke"
        token = credentials.token
        revoke_response = requests.post(
            revoke_endpoint,
            params={"token": token},
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

        if revoke_response.status_code == 200:
            # print("Google account successfully revoked.")
            ...
        else:
            # print("Failed to revoke Google account.")
            ...

        # Remove credentials from the session
        del request.session["credentials"]

        # Display a message to the user (optional)
        messages.success(request, "Your Google account has been successfully delinked.")
    else:
        messages.error(request, "No linked Google account found.")

    return redirect("profile")


# --------------------------------- #
# User + Fitness Trainer Functions  #
# --------------------------------- #
def fitness_trainer_application_view(request):
    user_id = request.session.get("user_id")
    if request.method == "POST":
        form = FitnessTrainerApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            past_experience_trainer = form.cleaned_data.get("past_experience_trainer")
            past_experience_dietician = form.cleaned_data.get(
                "past_experience_dietician"
            )
            resume = request.FILES["resume"]
            certifications = request.FILES.get("certifications")
            reference_name = form.cleaned_data.get("reference_name")
            reference_contact = form.cleaned_data.get("reference_contact")
            # Call the DynamoDB function, making sure all names match
            add_fitness_trainer_application(
                user_id=user_id,
                past_experience_trainer=past_experience_trainer,
                past_experience_dietician=past_experience_dietician,
                resume=resume,
                certifications=certifications,
                reference_name=reference_name,
                reference_contact=reference_contact,
            )
            # Notify user and redirect
            messages.success(
                request, "Your application has been submitted successfully!"
            )
            return redirect("profile")
    else:
        form = FitnessTrainerApplicationForm()
    return render(request, "fitness_trainer_application.html", {"form": form})


def fitness_trainer_applications_list_view(request):
    # Check if the current user is an admin
    user_id = request.session.get("user_id")
    user = get_user(user_id)
    if not user or not user.get("is_admin"):
        return HttpResponseForbidden("You do not have permission to access this page.")
    # Retrieve applications from DynamoDB
    applications = get_fitness_trainer_applications()
    # Render the list of applications
    return render(
        request,
        "fitness_trainer_applications_list.html",
        {"applications": applications},
    )


def approve_fitness_trainer(request):
    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        username = data.get("username")
        user = get_user_by_username(username)
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )
        make_fitness_trainer(user["user_id"])
        subject = "Fitness Trainer Application Approved"
        message = render_to_string(
            "fitness_trainer_email.html",
            {"username": username, "approval": True, "reason": ""},
        )
        senderEmail = "fiton.notifications@gmail.com"
        userEmail = user.get("email")
        email_message = EmailMessage(
            subject,
            message,
            senderEmail,
            [userEmail],
        )
        email_message.content_subtype = "html"
        email_message.send()
        return JsonResponse(
            {"status": "success", "message": "Fitness Trainer has been approved"}
        )
    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def reject_fitness_trainer(request):
    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        username = data.get("username")
        user = get_user_by_username(username)
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )
        remove_fitness_trainer(user["user_id"])
        subject = "Fitness Trainer Application Rejected"
        message = render_to_string(
            "fitness_trainer_email.html",
            {
                "username": username,
                "approval": False,
                "reason": "We are not accepting fitness trainers right now, please try again later",
            },
        )
        senderEmail = "fiton.notifications@gmail.com"
        userEmail = user.get("email")
        email_message = EmailMessage(
            subject,
            message,
            senderEmail,
            [userEmail],
        )
        email_message.content_subtype = "html"
        email_message.send()
        return JsonResponse(
            {"status": "success", "message": "Fitness Trainer application rejected"}
        )
    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def accept_trainer(request):
    if request.method == "POST":
        data = json.loads(request.body)
        trainer_id = data.get("trainer_id")
        user_id = request.session.get("user_id")
        trainer = get_user(trainer_id)
        user = get_user(user_id)
        if not user or not trainer:
            return JsonResponse({"status": "error", "message": "User is not found"})
        # Update access lists in DynamoDB
        add_to_list(user_id, "trainers_with_access", trainer_id)
        add_to_list(trainer_id, "users_with_access", user_id)
        # # Remove trainer from the user's waiting list
        remove_from_list(user_id, "waiting_list_of_trainers", trainer_id)
        remove_from_list(trainer_id, "waiting_list_of_users", user_id)
        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error", "message": "Invalid request"})


def deny_trainer(request):
    if request.method == "POST":
        data = json.loads(request.body)
        trainer_id = data.get("trainer_id")
        user_id = request.session.get("user_id")
        trainer = get_user(trainer_id)
        user = get_user(user_id)
        if not user or not trainer:
            return JsonResponse({"status": "error", "message": "User is not found"})
        # Remove trainer from the user's waiting list
        remove_from_list(user_id, "waiting_list_of_trainers", trainer_id)
        remove_from_list(trainer_id, "waiting_list_of_users", user_id)
        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error", "message": "Invalid request"})


def provide_access_to_trainer(request):
    if request.method == "POST":
        data = json.loads(request.body)
        trainer_id = data.get("trainer_id")
        user_id = request.session.get("user_id")
        trainer = get_user(trainer_id)
        user = get_user(user_id)
        if not user or not trainer:
            return JsonResponse({"status": "error", "message": "User is not found"})
        # Update user and trainer records in DynamoDB
        add_to_list(user_id, "trainers_with_access", trainer_id)
        add_to_list(trainer_id, "users_with_access", user_id)
        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error", "message": "Invalid request"})


def revoke_access_to_trainer(request):
    if request.method == "POST":
        data = json.loads(request.body)
        trainer_id = data.get("trainer_id")
        user_id = request.session.get("user_id")
        if not user_id or not trainer_id:
            return JsonResponse({"status": "error", "message": "Invalid data"})
        try:
            remove_from_list(user_id, "trainers_with_access", trainer_id)
            remove_from_list(trainer_id, "users_with_access", user_id)
            return JsonResponse(
                {
                    "status": "success",
                    "message": f"Revoked access for Trainer: {trainer_id}",
                }
            )
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})
    else:
        return JsonResponse({"status": "error", "message": "Invalid request method"})


def fitness_trainers_list_view(request):
    # Make sure that the current user is not a fitness trainer
    user_id = request.session.get("user_id")
    user = get_user(user_id)
    if not user or user.get("is_fitness_trainer"):
        return HttpResponseForbidden("You do not have permission to access this page")
    # Retrieve list of trainers from DynamoDB
    trainers = get_fitness_trainers()
    # Extract lists from the user's data
    waiting_list_of_trainers = user.get("waiting_list_of_trainers", [])
    trainers_with_access = user.get("trainers_with_access", [])
    # Separate trainers into categories
    trainers_in_waiting_list = [
        trainer
        for trainer in trainers
        if trainer["user_id"] in waiting_list_of_trainers
    ]
    my_trainers = [
        trainer for trainer in trainers if trainer["user_id"] in trainers_with_access
    ]
    remaining_trainers = [
        trainer
        for trainer in trainers
        if trainer["user_id"] not in waiting_list_of_trainers
        and trainer["user_id"] not in trainers_with_access
    ]
    # Pass the categorized trainers to the template
    context = {
        "trainers_in_waiting_list": trainers_in_waiting_list,
        "my_trainers": my_trainers,
        "remaining_trainers": remaining_trainers,
    }
    return render(request, "fitness_trainers_list.html", context)


def standard_users_list_view(request):
    # Check if the current user is a verified fitness trainer
    user_id = request.session.get("user_id")
    user = get_user(user_id)
    if not user or not user.get("is_fitness_trainer"):
        return HttpResponseForbidden("You do not have permission to access this page")
    # Retrieve list of standard users from DynamoDB
    standard_users = get_standard_users()
    waiting_list_of_users = user.get("waiting_list_of_users", [])
    users_in_waiting_list = [
        user for user in standard_users if user["user_id"] in waiting_list_of_users
    ]
    users_with_access = user.get("users_with_access", [])
    my_users = [user for user in standard_users if user["user_id"] in users_with_access]
    remaining_users = [
        user
        for user in standard_users
        if user["user_id"] not in waiting_list_of_users + users_with_access
    ]
    return render(
        request,
        "standard_users_list.html",
        {
            "users_in_waiting_list": users_in_waiting_list,
            "my_users": my_users,
            "remaining_users": remaining_users,
        },
    )


def send_data_request(request):
    if request.method == "POST":
        data = json.loads(request.body)
        standard_user_id = data.get("user_id")
        fitness_trainer_id = request.session.get("user_id")
        success = send_data_request_to_user(fitness_trainer_id, standard_user_id)
        if success:
            return JsonResponse({"message": "Request sent successfully!"}, status=200)
        else:
            return JsonResponse({"error": "Failed to send request"}, status=400)
    return JsonResponse({"error": "Invalid request"}, status=400)


def cancel_data_request(request):
    if request.method == "POST":
        data = json.loads(request.body)
        standard_user_id = data.get("user_id")
        fitness_trainer_id = request.session.get("user_id")
        if not standard_user_id:
            return JsonResponse({"error": "User ID is required"}, status=400)
        success = cancel_data_request_to_user(fitness_trainer_id, standard_user_id)
        if success:
            return JsonResponse(
                {"message": "Request cancelled successfully"}, status=200
            )
        else:
            return JsonResponse({"error": "Failed to cancel the request"}, status=400)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)


def view_user_data(request):
    print("view_user_data is being called")
    try:
        # Retrieve the data from the session
        user_data = request.session.get("user_data")
        print("User data in session:", user_data)
        if not user_data:
            # Handle missing session data
            raise ValueError("User data is not available in the session.")
        # Render the HTML template with the session data
        return render(
            request,
            "view_user_data.html",
            {
                "user_data": user_data,
            },
        )
    except Exception as e:
        # Handle errors
        return render(
            request,
            "view_user_data.html",
            {
                "error": str(e),
            },
        )


def store_session_data(request, user_data):
    # Store data in the session
    request.session["user_data"] = user_data
    request.session.modified = True  # Ensure the session is marked as modified
    print(request.session.get("user_data"))
    return


def serialize_data(data):
    # Handle dictionaries
    if isinstance(data, dict):
        return {key: serialize_data(value) for key, value in data.items()}
    # Handle lists and tuples
    elif isinstance(data, list) or isinstance(data, tuple):
        return [serialize_data(item) for item in data]
    # Handle dates: Convert datetime.date to ISO format string
    elif isinstance(data, dt.date):
        return data.isoformat()
    # Handle other types that can be directly serialized to JSON
    elif isinstance(data, (str, int, float, bool)):
        return data
    # If we can't serialize the type, return it as a string
    return str(data)


# Updated code for async_view_user_data
async def async_view_user_data(request, user_id):
    try:
        # Fetch the user data asynchronously
        user = await sync_to_async(get_user)(user_id)
        user_email = user.get("email")
        user_data = await fetch_user_data(user_email)
        # Serialize user data
        serialized_data = serialize_data(user_data)
        # Store the data in the session
        await sync_to_async(store_session_data)(request, serialized_data)
        # Send serialized user_data in JSON response
        return JsonResponse({"success": True, "user_data": serialized_data})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# -------------------------------
# Forums Functions
# -------------------------------


# View to display a single thread with its posts
def thread_detail_view(request, thread_id):
    # Fetch thread details from DynamoDB
    thread = threads_table.get_item(Key={"ThreadID": thread_id}).get("Item")
    posts = fetch_posts_for_thread(thread_id)  # Fetch replies related to the thread
    if not thread:
        return JsonResponse(
            {"status": "error", "message": "Thread not found"}, status=404
        )

    user_id = request.session.get("user_id")

    user = get_user(user_id)

    is_banned = user.get("is_banned")
    if is_banned:
        return render(request, "forums.html", {"is_banned": is_banned})

    user_id = request.session.get("username")  # Assuming user is logged in

    if request.method == "POST":
        if request.headers.get("x-requested-with") == "XMLHttpRequest":

            # Parse the AJAX request data
            data = json.loads(request.body.decode("utf-8"))
            action = data.get("action")
            post_id = data.get("post_id")
            # print("Action received:", action)  # Print the action value

            if action == "like_post":
                # Handle like/unlike for the main thread post
                liked_by = thread.get("LikedBy", [])
                if user_id in liked_by:
                    # Unlike logic
                    likes = max(0, thread.get("Likes", 0) - 1)
                    liked_by.remove(user_id)
                else:
                    # Like logic
                    likes = thread.get("Likes", 0) + 1
                    liked_by.append(user_id)
                threads_table.update_item(
                    Key={"ThreadID": thread_id},
                    UpdateExpression="SET Likes=:l, LikedBy=:lb",
                    ExpressionAttributeValues={":l": likes, ":lb": liked_by},
                )
                return JsonResponse(
                    {"status": "success", "likes": likes, "liked": user_id in liked_by}
                )

            elif action == "like_comment":
                # Handle like/unlike for a comment
                post = posts_table.get_item(
                    Key={"PostID": post_id, "ThreadID": thread_id}
                ).get("Item")
                if not post:
                    return JsonResponse(
                        {"status": "error", "message": "Comment not found"}, status=404
                    )

                liked_by = post.get("LikedBy", [])
                if user_id in liked_by:
                    # Unlike logic
                    likes = max(0, post.get("Likes", 0) - 1)
                    liked_by.remove(user_id)
                else:
                    # Like logic
                    likes = post.get("Likes", 0) + 1
                    liked_by.append(user_id)
                posts_table.update_item(
                    Key={"PostID": post_id, "ThreadID": thread_id},
                    UpdateExpression="SET Likes=:l, LikedBy=:lb",
                    ExpressionAttributeValues={":l": likes, ":lb": liked_by},
                )
                return JsonResponse(
                    {"status": "success", "likes": likes, "liked": user_id in liked_by}
                )

            elif action == "report_comment":
                # Handle report for a comment (you can define reporting logic here)
                # For simplicity, let's say reporting just returns a success message
                return JsonResponse(
                    {"status": "success", "message": "Comment reported successfully!"}
                )

            elif action == "add_reply":
                # print("add reply")

                # Handle adding a reply to a comment
                reply_content = data.get("content", "").strip()
                if not reply_content:
                    return JsonResponse(
                        {"status": "error", "message": "Reply content cannot be empty!"}
                    )

                # create reply
                reply_id = create_reply(
                    post_id=post_id,
                    thread_id=thread_id,
                    user_id=user_id,
                    content=reply_content,
                )
                # Return success and the reply content with the username
                return JsonResponse(
                    {
                        "status": "success",
                        "content": reply_content,
                        "username": user_id,
                        "reply_id": reply_id,
                    }
                )

            # Get the list of users who have liked the thread
            liked_by = thread.get("LikedBy", [])

            if user_id in liked_by:
                # If user has already liked the post, "unlike" (remove the like)
                likes = max(
                    0, thread.get("Likes", 0) - 1
                )  # Ensure likes never go below 0
                liked_by.remove(user_id)  # Remove the user from the LikedBy list
            else:
                # If user hasn't liked the post, add a like
                likes = thread.get("Likes", 0) + 1
                liked_by.append(user_id)  # Add the current user to the LikedBy list

            # Update the thread with the new like count and LikedBy list
            threads_table.update_item(
                Key={"ThreadID": thread_id},
                UpdateExpression="set Likes=:l, LikedBy=:lb",
                ExpressionAttributeValues={":l": likes, ":lb": liked_by},
            )
            return JsonResponse(
                {"status": "success", "likes": likes, "liked": user_id in liked_by}
            )

        # Handle non-AJAX post submission for creating a new comment
        elif "content" in request.POST:
            # Add a new post to the thread
            new_content = request.POST.get("content").strip()
            if new_content:
                post_comment(thread_id=thread_id, user_id=user_id, content=new_content)

            # Redirect after posting to avoid resubmission on refresh
            return redirect("thread_detail", thread_id=thread_id)

        else:
            # Handle reply submission (non-AJAX form submission)
            content = request.POST.get("content")

            if content and user_id:
                post_comment(thread_id=thread_id, user_id=user_id, content=content)
                return redirect("thread_detail", thread_id=thread_id)

    return render(
        request,
        "thread_detail.html",
        {
            "user": user,
            "thread": thread,
            "posts": posts,
            "liked": user_id in thread.get("LikedBy", []),
        },
    )


def new_thread_view(request):
    user_id = request.session.get("user_id")

    # Fetch user details from DynamoDB
    user = get_user(user_id)

    if not user:
        messages.error(request, "User not found.")
        return redirect("login")

    if request.method == "POST":
        title = request.POST.get("title")
        content = request.POST.get("content")
        section = request.POST.get("section")
        user_id = request.session.get("username")  # Assuming the user is logged in

        if title and content and user_id:
            # Call your DynamoDB function to create a new thread
            create_thread(
                title=title, user_id=user_id, content=content, section=section
            )

            # Redirect to the forums page after successfully creating the thread
            return redirect("forum")
        else:
            # If something's missing, return the form with an error message
            return render(
                request, "new_thread.html", {"error": "All fields are required."}
            )

    # If the request method is GET, simply show the form
    return render(request, "new_thread.html")


def delete_post_view(request):

    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        try:

            data = json.loads(request.body.decode("utf-8"))
            post_id = data.get("post_id")
            thread_id = data.get("thread_id")  # Make sure you're getting thread_id too

            if not post_id or not thread_id:
                return JsonResponse(
                    {"status": "error", "message": "Post or Thread ID missing"},
                    status=400,
                )

            # Call the delete_post function to delete from DynamoDB
            if delete_post(post_id, thread_id):
                return JsonResponse({"status": "success"})
            else:
                return JsonResponse(
                    {"status": "error", "message": "Failed to delete post"}, status=500
                )

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)
    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def forum_view(request):

    user_id = request.session.get("username")
    user = get_user_by_username(user_id)
    if not user:
        messages.error(request, "User not found.")
        return redirect("login")
    is_banned = user.get("is_banned")
    if is_banned:
        return render(request, "forums.html", {"is_banned": is_banned})

    # Get filter inputs from the request's GET parameters
    username = request.GET.get("username", "")  # Username filter
    thread_type = request.GET.get("type", "all")  # Thread or Reply filter
    start_date = request.GET.get("start_date", "")  # Start date filter
    end_date = request.GET.get("end_date", "")  # End date filter
    search_text = request.GET.get("search", "")  # Search text filter

    # Fetch section stats
    sections = ["General", "Workout Suggestions", "Diet Plans", "Other"]
    section_stats = {section: get_section_stats(section) for section in sections}

    # Fetch filtered threads based on the inputs
    threads = fetch_filtered_threads(
        username=username,
        thread_type=thread_type,
        start_date=start_date,
        end_date=end_date,
        search_text=search_text,
    )

    # Fetch all users for the dropdown filter
    users = (
        fetch_all_users()
    )  # Assuming you have a function to fetch users who posted threads/replies

    return render(
        request,
        "forums.html",
        {
            "threads": threads,
            "users": users,
            "user": user,
            "section_stats": section_stats,
        },
    )


def section_view(request, section_name):
    user_id = request.session.get("username")
    user = get_user_by_username(user_id)

    if not user:
        messages.error(request, "User not found.")
        return redirect("login")

    is_banned = user.get("is_banned")
    if is_banned:
        return render(request, "forums.html", {"is_banned": is_banned})

    # Fetch threads only for the specified section
    threads = fetch_filtered_threads(section=section_name)
    threads = sorted(threads, key=lambda t: t.get("CreatedAt"), reverse=True)

    return render(
        request,
        "section_threads.html",
        {"threads": threads, "section_name": section_name, "user": user},
    )


######################################
#       Fetching data using API     #
######################################


async def format_bod_fitness_data(total_data):
    list1 = total_data["glucose"]["glucose_data_json"]
    list2 = total_data["pressure"]["pressure_data_json"]

    def parse_date(date_str):
        return dt.datetime.strptime(date_str, "%b %d, %I %p")

    # Extract all unique start dates from both lists
    all_dates = set()
    for item in list1 + list2:
        all_dates.add(item["start"])

    # Update list1
    for date in all_dates:
        found = False
        for item in list1:
            if item["start"] == date:
                found = True
                break
        if not found:
            list1.append({"start": date, "end": date, "count": 0})

    # Update list2
    for date in all_dates:
        found = False
        for item in list2:
            if item["start"] == date:
                found = True
                break
        if not found:
            list2.append({"start": date, "end": date, "count": 0})

    # Sort lists by start date
    list1.sort(key=lambda x: parse_date(x["start"]))
    list2.sort(key=lambda x: parse_date(x["start"]))

    total_data["glucose"]["glucose_data_json"] = list1
    total_data["pressure"]["pressure_data_json"] = list2

    return total_data


def process_dynamo_data(items, frequency):
    # Dictionary to hold the data grouped by date
    # print("Items in dictionary", items)
    date_groups = defaultdict(list)

    # Process each item
    for item in items:
        time = dt.datetime.strptime(item["time"], "%Y-%m-%dT%H:%M")
        start, end = get_group_key(time, frequency)
        start_key = start.strftime("%b %d, %I %p")
        end_key = end.strftime("%b %d, %I %p")
        value = float(item["value"])
        date_groups[(start_key, end_key)].append(value)

    # Prepare the final data structure
    result = []

    for (start_key, end_key), values in date_groups.items():
        avg_count = sum(values) / len(values) if values else 0
        result.append(
            {
                "start": start_key,
                "end": end_key,
                "count": avg_count,
            }
        )

    return {"Items": result}


# function to convert miliseconds to Day
def parse_millis(millis):
    return dt.datetime.fromtimestamp(int(millis) / 1000).strftime("%b %d, %I %p")


def get_group_key(time, frequency):
    """Adjusts start and end times based on frequency."""
    if frequency == "hourly":
        start = time.replace(minute=0, second=0, microsecond=0)
        end = start + dt.timedelta(hours=1)
    elif frequency == "daily":
        start = time.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + dt.timedelta(days=1)
    elif frequency == "weekly":
        start = time - dt.timedelta(days=time.weekday())
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + dt.timedelta(days=7)
    elif frequency == "monthly":
        start = time.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = start + dt.timedelta(
            days=(time.replace(month=time.month % 12 + 1, day=1) - time).days
        )
    else:
        start = time  # Fallback to the exact time if frequency is unrecognized
        end = time

    return start, end


def merge_data(existing_data, new_data, frequency):
    """
    Merges new data into existing data based on overlapping time ranges defined by frequency.

    Parameters:
    existing_data (list): The existing list of data points for a metric.
    new_data (list): The new data points to be merged.
    frequency (str): The frequency of data collection ('hourly', 'daily', 'weekly', 'monthly').

    Returns:
    list: Updated list of data points after merging.
    """

    # Helper to parse datetime from string
    def parse_time(time_str):
        return dt.datetime.strptime(time_str, "%b %d, %I %p")

    # Create index of existing data by start time for quick access
    data_index = {}
    for item in existing_data:
        start, end = get_group_key(parse_time(item["start"]), frequency)
        data_index[start] = item
        item["end_range"] = end  # Temporarily store the range end to use in comparisons

    # Process each new data point
    for new_item in new_data:
        new_start, new_end = get_group_key(parse_time(new_item["start"]), frequency)
        if new_start in data_index:
            # There's an overlap, so update the existing entry
            existing_item = data_index[new_start]
            # Averaging the counts, updating mins and maxs
            existing_item["count"] = (existing_item["count"] + new_item["count"]) / 2
            if min in existing_item or min in new_item:
                existing_item["min"] = (
                    new_item["min"]
                    if "min" not in existing_item
                    else min(existing_item["min"], new_item["min"])
                )
                existing_item["max"] = (
                    new_item["max"]
                    if "max" not in existing_item
                    else max(existing_item["max"], new_item["max"])
                )
        else:
            # No overlap, append this new item
            new_item["end"] = new_end.strftime(
                "%b %d, %I %p"
            )  # Format end time for consistency
            existing_data.append(new_item)

    # Remove temporary 'end_range' from existing items
    for item in existing_data:
        item.pop("end_range", None)

    existing_data.sort(key=lambda x: parse_time(x["start"]))

    combined_data = []
    for obj in existing_data:
        if not combined_data or parse_time(combined_data[-1]["start"]) != parse_time(
            obj["start"]
        ):
            combined_data.append(obj)
        else:
            combined_data[-1]["count"] += obj["count"]

    return combined_data


def steps_barplot(data):
    # Your steps data
    # print("inside steps function\n")
    steps_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = record["dataset"][0]["point"][0]["value"][0]["intVal"]
            steps_data.append(d)

    # Pass the plot path to the template
    # print("Steps Data:", steps_data)
    context = {"steps_data_json": steps_data}
    return context


def resting_heartrate_plot(data):
    # print("inside resting heart function\n")
    resting_heart_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = int(record["dataset"][0]["point"][0]["value"][0]["fpVal"])
            resting_heart_data.append(d)

    # Pass the plot path to the template
    context = {"resting_heart_data_json": resting_heart_data}
    return context


def sleep_plot(data):
    # print("inside sleep function\n")
    sleep_data = []
    for record in data["session"]:
        d = {}
        d["start"] = parse_millis(record["startTimeMillis"])
        d["end"] = parse_millis(record["endTimeMillis"])
        d["count"] = (
            (int(record["endTimeMillis"]) - int(record["startTimeMillis"]))
            / 1000
            / 60
            / 60
        )
        sleep_data.append(d)

    # Pass the plot path to the template
    context = {"sleep_data_json": sleep_data}
    return context


def heartrate_plot(data):
    # print("inside heart function\n")
    heart_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = float(record["dataset"][0]["point"][0]["value"][0]["fpVal"])
            d["min"] = int(record["dataset"][0]["point"][0]["value"][1]["fpVal"])
            d["max"] = int(record["dataset"][0]["point"][0]["value"][2]["fpVal"])
            heart_data.append(d)

    # Pass the plot path to the template
    context = {"heart_data_json": heart_data}
    return context


def activity_plot(data):
    # print("inside activity function\n")
    activity_data = {}
    for record in data["session"]:
        activity_name = df.loc[df["Integer"] == record["activityType"]][
            "Activity Type"
        ].values
        if len(activity_name) == 0:
            continue
        act = activity_name[0]
        duration = (
            (int(record["endTimeMillis"]) - int(record["startTimeMillis"])) / 1000 / 60
        )
        if act in activity_data:
            activity_data[act] += int(duration)
        else:
            activity_data[act] = int(duration)

    activity_data = sorted(activity_data.items(), key=lambda x: x[1], reverse=True)
    activity_data = activity_data[:10]

    # Pass the plot path to the template
    context = {"activity_data_json": activity_data}
    return context


def oxygen_plot(data):
    # print("inside oxygen saturation function\n")
    oxygen_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = int(record["dataset"][0]["point"][0]["value"][0]["fpVal"])
            oxygen_data.append(d)

    # Pass the plot path to the template
    context = {"oxygen_data_json": oxygen_data}
    return context


def glucose_plot(data):
    # print("inside blood glucose function\n")
    oxygen_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = int(record["dataset"][0]["point"][0]["value"][0]["fpVal"])
            oxygen_data.append(d)

    # Pass the plot path to the template
    context = {"glucose_data_json": oxygen_data}
    return context


def pressure_plot(data):
    # print("inside blood pressure function\n")
    oxygen_data = []
    for record in data["bucket"]:
        if len(record["dataset"][0]["point"]) == 0:
            continue
        else:
            d = {}
            d["start"] = parse_millis(record["startTimeMillis"])
            d["end"] = parse_millis(record["endTimeMillis"])
            d["count"] = int(record["dataset"][0]["point"][0]["value"][0]["fpVal"])
            oxygen_data.append(d)

    # Pass the plot path to the template
    context = {"pressure_data_json": oxygen_data}
    return context


async def fetch_metric_data(service, metric, total_data, duration, frequency, email):

    end_time = dt.datetime.now() - dt.timedelta(minutes=1)

    if duration == "day":
        start_time = end_time - dt.timedelta(hours=23, minutes=59)
    elif duration == "week":
        start_time = end_time - dt.timedelta(days=6, hours=23, minutes=59)
    elif duration == "month":
        start_time = end_time - dt.timedelta(days=29, hours=23, minutes=59)
    elif duration == "quarter":
        start_time = end_time - dt.timedelta(days=89, hours=23, minutes=59)

    if frequency == "hourly":
        bucket = 3600000
    elif frequency == "daily":
        bucket = 86400000
    elif frequency == "weekly":
        bucket = 604800000
    elif frequency == "monthly":
        bucket = 2592000000

    start_date = start_time.astimezone(pytz.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    end_date = end_time.astimezone(pytz.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    if metric == "sleep":
        data = (
            service.users()
            .sessions()
            .list(
                userId="me",
                activityType=72,
                startTime=f"{start_date}",
                endTime=f"{end_date}",
            )
            .execute()
        )
    elif metric == "activity":
        data = (
            service.users()
            .sessions()
            .list(userId="me", startTime=f"{start_date}", endTime=f"{end_date}")
            .execute()
        )
    else:
        data = (
            service.users()
            .dataset()
            .aggregate(
                userId="me",
                body={
                    "aggregateBy": [{"dataTypeName": dataTypes[metric]}],
                    "bucketByTime": {"durationMillis": bucket},
                    "startTimeMillis": int(start_time.timestamp()) * 1000,
                    "endTimeMillis": int(end_time.timestamp()) * 1000,
                },
            )
            .execute()
        )

    if metric == "heart_rate":
        context = heartrate_plot(data)
        total_data["heartRate"] = context
    elif metric == "steps":
        context = steps_barplot(data)
        total_data["steps"] = context
    elif metric == "resting_heart_rate":
        context = resting_heartrate_plot(data)
        total_data["restingHeartRate"] = context
    elif metric == "sleep":
        context = sleep_plot(data)
        total_data["sleep"] = context
    elif metric == "activity":
        context = activity_plot(data)
        total_data["activity"] = context
    elif metric == "oxygen":
        context = oxygen_plot(data)
        total_data["oxygen"] = context
    elif metric == "glucose":
        context = glucose_plot(data)
        total_data["glucose"] = context
    elif metric == "pressure":
        context = pressure_plot(data)
        total_data["pressure"] = context
    response = get_fitness_data(metric, email, start_time, end_time)
    # print(
    #     f"Metric : {metric}\nResponse: {response}\n",
    # )
    # print("printing processed data from DynamoDB--------------------------------")

    processed_data = process_dynamo_data(response["Items"], frequency)
    # print("processed data", processed_data)

    # Assuming 'processed_data' is structured similarly for each metric
    # and 'frequency' is defined appropriately for the context in which this is run

    if metric == "heart_rate":
        # print("heart rate")
        total_data["heartRate"]["heart_data_json"] = merge_data(
            total_data["heartRate"]["heart_data_json"],
            processed_data["Items"],
            frequency,
        )
    elif metric == "steps":
        # print("steps")
        total_data["steps"]["steps_data_json"] = merge_data(
            total_data["steps"]["steps_data_json"], processed_data["Items"], frequency
        )
    elif metric == "resting_heart_rate":
        # print("resting heart rate")
        total_data["restingHeartRate"]["resting_heart_data_json"] = merge_data(
            total_data["restingHeartRate"]["resting_heart_data_json"],
            processed_data["Items"],
            frequency,
        )
    elif metric == "sleep":
        # print("sleep")
        total_data["sleep"]["sleep_data_json"] = merge_data(
            total_data["sleep"]["sleep_data_json"], processed_data["Items"], frequency
        )
    elif metric == "activity":
        # print("activity")
        print()
        # final = merge_data(total_data['activity']['activity_data_json'], processed_data['Items'], frequency)
        # print(final) #

    elif metric == "oxygen":
        # print("oxygen")
        total_data["oxygen"]["oxygen_data_json"] = merge_data(
            total_data["oxygen"]["oxygen_data_json"], processed_data["Items"], frequency
        )
    else:
        print("Unknown metric")


async def get_sleep_scores(request, total_data):
    sleep_body = ""
    for sleep_data in total_data["sleep"]["sleep_data_json"]:
        duration = sleep_data["count"]
        user_id = request.session.get("user_id")
        user = get_user(user_id)
        age = 26
        activity_level = 70
        given_date = dt.datetime.strptime(sleep_data["start"], "%b %d, %I %p")
        nearest_hr = min(
            total_data["restingHeartRate"]["resting_heart_data_json"],
            key=lambda x: abs(
                dt.datetime.strptime(x["start"], "%b %d, %I %p") - given_date
            ),
        )
        heart_rate = nearest_hr["count"]

        nearest_steps = min(
            total_data["steps"]["steps_data_json"],
            key=lambda x: abs(
                dt.datetime.strptime(x["start"], "%b %d, %I %p") - given_date
            ),
        )
        daily_steps = nearest_steps["count"]

        gender_female = user.get("gender") == "F"
        gender_male = user.get("gender") == "M"

        sleep_body += f"""{age},{duration},{activity_level},{heart_rate},{daily_steps},
        {gender_female},{gender_male},{True},{True},{False},{False},{False},{False}\n"""

    if sleep_body and sleep_body[-1] == "\n":
        sleep_body = sleep_body[:-1]

    url = "https://9pweqg5b1i.execute-api.us-west-2.amazonaws.com/dev/inference"

    response = requests.post(url, json=sleep_body)
    print("Response:", response)
    sleep_score = response.text.split(":")[1][:-1].strip()
    try:
        sleep_score = ast.literal_eval(sleep_score)
        print("Sleep Score:", sleep_score)

    except Exception as e:
        print(e)
    for i, sleep_data in enumerate(total_data["sleep"]["sleep_data_json"]):
        sleep_data["count"] = sleep_score[i]
    print("Total Data:", total_data)
    return total_data


@sync_to_async
def get_credentials(request):
    print("Request:", request)
    if "credentials" in request.session:
        credentials = Credentials(**request.session["credentials"])
        return credentials, request.user.username
    return None, None


async def fetch_all_metric_data(request, duration, frequency):
    total_data = {}
    credentials, email = await get_credentials(request)
    print(f"Credentails: {credentials}. Email: {email}")

    user_id = request.session.get("user_id")
    user = get_user(user_id)
    email = user.get("email")
    if credentials:
        # try:
        service = build("fitness", "v1", credentials=credentials)
        tasks = []
        for metric in dataTypes.keys():
            tasks.append(
                fetch_metric_data(
                    service, metric, total_data, duration, frequency, email
                )
            )

        await asyncio.gather(*tasks)
        total_data = await get_sleep_scores(request, total_data)
        total_data = await format_bod_fitness_data(total_data)

        # except Exception as e:
        #     print(e)
        #     total_data = {}

    else:
        print("Not Signed in Google")
    print("total data: ", total_data)
    return total_data


async def get_metric_data(request):
    credentials = await sync_to_async(lambda: request.session.get("credentials"))()
    user_id = await sync_to_async(lambda: request.session.get("user_id"))()
    user = get_user(user_id)
    user_email = user.get("email")
    # print("Credentials: \n", credentials)
    # print("User Email: \n", user_email)
    if credentials:
        duration = "week"
        frequency = "daily"

        if request.GET.get("data_drn"):
            duration = request.GET.get("data_drn")

        if request.GET.get("data_freq"):
            frequency = request.GET.get("data_freq")

        total_data = await fetch_all_metric_data(request, duration, frequency)
        rds_response = await rds_main(user_email, total_data)
        print("RDS Response: \n", rds_response)
        context = {"data": total_data}
        # print("Inside get metric:", context)
        return await sync_to_async(render)(
            request, "display_metrics_data.html", context
        )
    else:
        await add_message(
            request,
            messages.ERROR,
            "User not logged in. Please sign in to access your data.",
        )
        return await perform_redirect("profile")


def health_data_view(request):
    user_id = request.session.get("user_id")
    user = get_user(user_id)
    user_email = user.get("email")
    dynamodb_res = dynamodb
    table = dynamodb_res.Table("UserFitnessData")

    if request.method == "POST":
        data = request.POST
        print("Data:", data)
        try:
            table.put_item(
                Item={
                    "email": user_email,  # Use the default email
                    "metric": data.get("metric"),
                    "time": data.get("time"),
                    "value": data.get("value"),
                },
                ConditionExpression="attribute_not_exists(email) AND attribute_not_exists(#t)",
                ExpressionAttributeNames={"#t": "time"},
            )
        except dynamodb_res.meta.client.exceptions.ConditionalCheckFailedException:
            print("Item already exists and was not replaced.")
        return redirect("get_metric_data")

    # Fetch all the metrics data from DynamoDB
    response = table.scan()
    metrics_data = {}
    for item in response["Items"]:
        metric = item["metric"]
        if metric not in metrics_data:
            metrics_data[metric] = []
        metrics_data[metric].append(item)

    for metric in metrics_data:
        metrics_data[metric].sort(key=lambda x: x["time"], reverse=True)

    return render(request, "display_metrics_data.html", {"metrics_data": metrics_data})


def add_reply(request):
    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        try:
            data = json.loads(request.body.decode("utf-8"))

            post_id = data.get("post_id")
            content = data.get("content")
            thread_id = data.get("thread_id")

            if not post_id or not content:
                return JsonResponse(
                    {"status": "error", "message": "Post ID and content are required."},
                    status=400,
                )

            user_id = request.session.get("username")
            if not user_id:
                return JsonResponse(
                    {"status": "error", "message": "User not authenticated"}, status=403
                )

            # tz = timezone("EST")
            reply_data = {
                "ReplyID": str(uuid.uuid4()),
                "UserID": user_id,
                "Content": content,
                # "CreatedAt": datetime.now(tz).isoformat(),
            }

            # Simulating interaction with a database (DynamoDB, for example)
            # print("Attempting to save reply:", reply_data)  # Debugging statement
            # Assuming 'posts_table' is configured to interact with your database
            posts_table.update_item(
                Key={"PostID": post_id, "ThreadID": thread_id},
                UpdateExpression="SET Replies = list_append(if_not_exists(Replies, :empty_list), :reply)",
                ExpressionAttributeValues={":reply": [reply_data], ":empty_list": []},
                ReturnValues="UPDATED_NEW",
            )

            return JsonResponse(
                {
                    "status": "success",
                    "reply_id": reply_data["ReplyID"],
                    "content": content,
                    "username": user_id,
                    # "created_at": reply_data["CreatedAt"],
                }
            )

        except Exception as e:
            print("Exception occurred:", e)  # Debugging statement
            return JsonResponse(
                {"status": "error", "message": f"Failed to save reply: {str(e)}"},
                status=500,
            )

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def delete_reply_view(request):
    # print("ReplitID:")
    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body.decode("utf-8"))
        post_id = data.get("post_id")
        reply_id = data.get("reply_id")
        thread_id = data.get("thread_id")  # Retrieve thread_id from the request data

        if not post_id or not reply_id:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Post ID, Reply ID and Thread ID are required.",
                },
                status=400,
            )

        # Call the delete_reply function in dynamodb.py
        result = delete_reply(post_id, thread_id, reply_id)

        if result.get("status") == "success":
            return JsonResponse({"status": "success"})
        else:
            error_message = result.get(
                "message", "An error occurred while deleting the reply."
            )
            return JsonResponse(
                {"status": "error", "message": error_message}, status=500
            )

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def delete_thread(request):
    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body.decode("utf-8"))
        thread_id = data.get("thread_id")

        if not thread_id:
            return JsonResponse(
                {"status": "error", "message": "Thread ID is required."}, status=400
            )

        try:
            # Perform the deletion from DynamoDB
            delete_thread_by_id(thread_id)
            # threads_table.delete_item(Key={"ThreadID": thread_id})
            return JsonResponse(
                {"status": "success", "message": "Thread deleted successfully."}
            )
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)
    return JsonResponse(
        {"status": "error", "message": "Invalid request method."}, status=400
    )


def reports_view(request):
    user = get_user(request.session.get("user_id"))
    reporting_user = user.get("user_id")  # Get the user ID from the session

    # Handle POST requests (Reporting Threads and Comments) - Available to all users
    if request.method == "POST":
        data = json.loads(request.body.decode("utf-8"))
        action = data.get("action")
        thread_id = data.get("thread_id")
        post_id = data.get("post_id")  # Add support for comment IDs

        # Debugging input values
        # print(f"Action: {action}, Thread ID: {thread_id}, Post ID: {post_id}")

        # Allow anyone to report a thread
        if action == "report_thread" and thread_id:
            # Mark the thread as reported in DynamoDB
            mark_thread_as_reported(thread_id)
            return JsonResponse({"status": "success"})

        # Allow anyone to report a comment
        elif action == "report_comment" and thread_id and post_id:
            # print("Reporting comment...")
            # Pass all three arguments to the function
            mark_comment_as_reported(thread_id, post_id, reporting_user)
            return JsonResponse(
                {
                    "status": "success",
                    "message": f"Comment {post_id} reported successfully.",
                }
            )

        return JsonResponse(
            {"status": "error", "message": "Invalid request"}, status=400
        )

    # Handle GET requests (View reported threads and comments) - Restricted to admins
    if not user.get("is_admin"):
        return redirect("forum")  # Redirect non-admins to the main forum page

    # Retrieve reported threads and comments (Only for admins)
    reported_data = fetch_reported_threads_and_comments()
    return render(request, "reports.html", reported_data)


# -----------------
# Ban User Function
# ------------------


# By username
def toggle_ban_user(request):
    dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
    users_table = dynamodb.Table("Users")

    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        username = data.get(
            "user_id"
        )  # Ensure this matches the 'user_id' field in DynamoDB

        if not username:
            return JsonResponse(
                {"status": "error", "message": "User ID is missing"}, status=400
            )

        # Fetch user to check if they exist
        user = get_user_by_username(username)
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )

        uid = user.get("user_id")
        # Toggle the 'is_banned' attribute
        is_banned = not user.get("is_banned", False)

        # Define the update expression and attributes
        update_expression = "set is_banned = :b"
        expression_values = {":b": is_banned}

        # If banning the user, set 'punishment_date' to the current time
        if is_banned:
            est = pytz.timezone("US/Eastern")
            punishment_date = datetime.now(est).isoformat()
            update_expression += ", punishment_date = :d"
            expression_values[":d"] = punishment_date
        else:
            # If unbanning, remove punishment_date attribute
            update_expression += " remove punishment_date"

        # Update the user item in DynamoDB
        users_table.update_item(
            Key={"user_id": uid},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
        )

        return JsonResponse({"status": "success", "is_banned": is_banned})

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def toggle_mute_user(request):
    dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
    users_table = dynamodb.Table("Users")

    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        username = data.get(
            "user_id"
        )  # Ensure this matches the 'user_id' field in DynamoDB

        if not username:
            return JsonResponse(
                {"status": "error", "message": "User ID is missing"}, status=400
            )

        # Fetch user to check if they exist
        user = get_user_by_username(username)
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )

        uid = user.get("user_id")
        # Toggle the 'is_banned' attribute
        is_muted = not user.get("is_muted", False)

        # Define the update expression and attributes
        update_expression = "set is_muted = :b"
        expression_values = {":b": is_muted}

        # If banning the user, set 'punishment_date' to the current time
        if is_muted:
            est = pytz.timezone("US/Eastern")
            punishment_date = datetime.now(est).isoformat()
            update_expression += ", punishment_date = :d"
            expression_values[":d"] = punishment_date
        else:
            # If unbanning, remove punishment_date attribute
            update_expression += " remove punishment_date"

        # Update the user item in DynamoDB
        users_table.update_item(
            Key={"user_id": uid},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
        )

        return JsonResponse({"status": "success", "is_muted": is_muted})

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def unban_user(request):
    dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
    users_table = dynamodb.Table("Users")

    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        user_id = data.get(
            "user_id"
        )  # Ensure this matches the 'user_id' field in DynamoDB

        if not user_id:
            return JsonResponse(
                {"status": "error", "message": "User ID is missing"}, status=400
            )

        # Fetch user to check if they exist
        if not user_id:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )

        # Set 'is_banned' to False and remove 'punishment_date'
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="set is_banned = :b remove punishment_date",
            ExpressionAttributeValues={":b": False},
        )

        return JsonResponse({"status": "success", "message": "User has been unbanned"})

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def unmute_user(request):
    dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
    users_table = dynamodb.Table("Users")

    if (
        request.method == "POST"
        and request.headers.get("x-requested-with") == "XMLHttpRequest"
    ):
        data = json.loads(request.body)
        user_id = data.get(
            "user_id"
        )  # Ensure this matches the 'user_id' field in DynamoDB
        if not user_id:
            return JsonResponse(
                {"status": "error", "message": "User ID is missing"}, status=400
            )

        # Fetch user to check if they exist
        if not user_id:
            return JsonResponse(
                {"status": "error", "message": "User not found"}, status=404
            )

        # Set 'is_banned' to False and remove 'punishment_date'
        users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="set is_muted = :b remove punishment_date",
            ExpressionAttributeValues={":b": False},
        )

        return JsonResponse({"status": "success", "message": "User has been unmuted"})

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def warn_action(request):
    if request.method == "POST":
        data = json.loads(request.body.decode("utf-8"))
        action = data.get("action")
        thread_id = data.get("thread_id")
        post_id = data.get("post_id")
        username = data.get("user_id")  # Here 'user_id' refers to the username.

        if not username:
            return JsonResponse(
                {"status": "error", "message": "Username is missing."}, status=400
            )

        # Retrieve the user record by username
        user = get_user_by_username(username)
        if not user:
            return JsonResponse(
                {"status": "error", "message": "User not found."}, status=404
            )

        # Extract the actual user_id from the user record
        user_id = user.get("user_id")

        print(
            f"Action: {action}, Thread ID: {thread_id}, Post ID: {post_id}, User ID: {user_id}"
        )

        if action == "warn_thread" and thread_id:
            mark_user_as_warned_thread(thread_id, user_id)
            return JsonResponse(
                {"status": "success", "message": "User warned for thread successfully."}
            )

        elif action == "warn_comment" and post_id:
            mark_user_as_warned_comment(post_id, user_id)
            return JsonResponse(
                {
                    "status": "success",
                    "message": "User warned for comment successfully.",
                }
            )

        return JsonResponse(
            {"status": "error", "message": "Invalid action or ID."}, status=400
        )

    return JsonResponse(
        {"status": "error", "message": "Invalid request method."}, status=405
    )


def dismiss_warning(request):
    if request.method == "POST":
        user_id = request.session.get("user_id")  # Retrieve the logged-in user's ID
        if not user_id:
            return JsonResponse(
                {"status": "error", "message": "User ID is missing."}, status=400
            )

        # Call the function to set is_warned to False
        result = set_user_warned_to_false(user_id)

        if result["status"] == "success":
            return JsonResponse({"status": "success", "message": result["message"]})
        else:
            return JsonResponse(
                {"status": "error", "message": result["message"]}, status=500
            )

    return JsonResponse(
        {"status": "error", "message": "Invalid request method."}, status=400
    )


# -------------
# Punishmentsx
# -------------


def punishments_view(request):
    # Check if the current user is an admin
    user_id = request.session.get("username")
    user = get_user_by_username(user_id)
    if not user or not user.get("is_admin"):
        return HttpResponseForbidden("You do not have permission to access this page.")

    # Fetch only punished users (banned or muted)
    dynamodb = boto3.resource("dynamodb", region_name="us-west-2")
    users_table = dynamodb.Table("Users")
    response = users_table.scan(
        FilterExpression="is_banned = :true OR is_muted = :true",
        ExpressionAttributeValues={":true": True},
    )
    punished_users = response.get("Items", [])

    # Pass the punished users to the template
    return render(request, "punishments.html", {"punished_users": punished_users})


# # ---------------------
# #   Sleep Score
# # ---------------------


def store_exercises(request):
    post_data = json.loads(request.body)
    exercise_list = post_data["data_list"]
    print("Exercises: ", exercise_list)
    connection = pymysql.connect(
        host="database-1.chu04k6u0syf.us-east-1.rds.amazonaws.com",
        user="admin",
        password="admin1234",
        database="exercises",
    )
    user = User.objects.get(email=request.user.username)
    success = False
    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO fitness_data (timestamp, user_id, Age, gender, height, weight, heartrate, steps, exercise_id) VALUES ("

            ts = datetime.datetime.now()
            # Iterate over the list of values and execute the query for each row
            for value in exercise_list:
                ts = ts - datetime.timedelta(seconds=1)
                time = ts.strftime("%Y-%m-%d %H:%M:%S.%f")
                temp_sql = str(sql)
                temp_sql += f'"{time}", '
                temp_sql += str(user.id)
                temp_sql += ", 26, "
                gender = 1 if user.sex == "male" else 0
                temp_sql += f"{gender}, "
                temp_sql += f"{user.height}, "
                temp_sql += f"{user.weight}, "
                temp_sql += "75, "
                temp_sql += "5000, "
                temp_sql += f"{value})"

                cursor.execute(temp_sql)

            # Commit the transaction
            connection.commit()
            print("Insertion of exercises successful")
            success = True

    finally:
        # Close the connection
        connection.close()

    if success:
        return JsonResponse({"message": "Data received successfully"})
    else:
        return JsonResponse({"error": "Insertion failed"}, status=500)


def list_exercises(request):
    print("Request:", request)
    name = request.GET.get("exercise_name")
    level = request.GET.get("exercise_level")
    equipment = request.GET.get("exercise_equipment")
    muscle = request.GET.get("exercise_muscle")
    category = request.GET.get("exercise_category")
    print(
        f"Name: {name}, Level:{level}, Equipment:{equipment}, Muscle: {muscle}, Category:{category}"
    )

    # user = User.objects.get(email=request.user.username)
    user_id = request.session.get("username")
    user = get_user_by_username(user_id)
    print("User:", user)

    gender = 1 if (user["gender"]) == "M" else 0
    body = f"{gender}, {user['height']}, {user['weight']}, 70, 5000"
    url = "https://9pweqg5b1i.execute-api.us-west-2.amazonaws.com/dev/recommend"
    response = requests.post(url, json=body).text
    print(f"Response:{response}")
    start_index = response.index("[")
    end_index = response.rindex("]")
    list_string = response[start_index : end_index + 1]
    print(f"List String: {list_string}")
    inference_list = eval(list_string)[0]
    print(f"Inference String: {inference_list}")
    # if(type(inference_list) == int):
    #     inference_list = [inference_list]
    # inference_list = [max(50+i, i) for i in inference_list]
    print(f"Inference String 2: {inference_list}")

    print(f"Request: {request}")
    selected_exercises = request.GET.getlist("exercise")
    print(f"Selected Exercises: {selected_exercises}")

    exercises = Exercise.objects.all()
    print(f"Exercises: {exercises}")

    if name:
        exercises = exercises.filter(name__icontains=name)
    if level and level != "none":
        exercises = exercises.filter(level__icontains=level)
    if equipment and equipment != "none":
        exercises = exercises.filter(equipment__icontains=equipment)
    if category and category != "none":
        exercises = exercises.filter(category__icontains=category)
    if muscle and muscle != "none":
        if MuscleGroup.objects.filter(name=muscle).exists():
            exercises = exercises.filter(
                primaryMuscles__name__icontains=muscle
            ) | exercises.filter(secondaryMuscles__name__icontains=muscle)

    filter_dict = {
        "name": name if name else "",
        "level": level if level else "none",
        "equipment": equipment if equipment else "none",
        "category": category if category else "none",
        "muscle": muscle if muscle else "none",
    }

    page_number = request.GET.get("page", 1)  # Default to page 1 if not provided
    paginator = Paginator(exercises, 10)

    try:
        exercises = paginator.page(page_number)
    except PageNotAnInteger:
        exercises = paginator.page(1)
    except EmptyPage:
        exercises = paginator.page(paginator.num_pages)

    current_page_number = exercises.number
    page_range = paginator.page_range
    num_pages = paginator.num_pages

    image_urls = []
    for ex in exercises:
        name = re.sub(r"[^a-zA-Z0-9-(),']", "_", ex.name)
        url = {
            "url_0": f"https://fiton-static-files.s3.us-west-2.amazonaws.com/exercise_images/{name}_0.jpg",
            "url_1": f"https://fiton-static-files.s3.us-west-2.amazonaws.com/exercise_images/{name}_1.jpg",
        }
        image_urls.append(url)
    print(f"Image URLS: {image_urls}")

    if selected_exercises and len(selected_exercises):
        selected_exercises = Exercise.objects.filter(id__in=selected_exercises)
    else:
        selected_exercises = []

    if inference_list and len(inference_list) == 4:
        recommended_exercises = Exercise.objects.filter(id__in=inference_list)
    else:
        recommended_exercises = []

    print(f"Recommended Exercises 1: {recommended_exercises}")

    recommended_image_urls = []
    for ex in recommended_exercises:
        name = re.sub(r"[^a-zA-Z0-9-(),']", "_", ex.name)
        url = {
            "url_0": f"https://fiton-static-files.s3.us-west-2.amazonaws.com/exercise_images/{name}_0.jpg",
            "url_1": f"https://fiton-static-files.s3.us-west-2.amazonaws.com/exercise_images/{name}_1.jpg",
        }
        recommended_image_urls.append(url)

    print(f"Recommended Exercises :{recommended_exercises}")

    return render(
        request,
        "exercise_list.html",
        {
            "exercises": zip(exercises, image_urls),
            "filter_dict": filter_dict,
            "current_page_number": current_page_number,
            "page_range": page_range,
            "num_pages": num_pages,
            "selected_exercises": selected_exercises,
            "recommended_exercises": zip(recommended_exercises, recommended_image_urls),
        },
    )


# -------------------------------
# Chat Functions
# -------------------------------

# def private_chat(request):
#     username = request.session.get("username")
#     user = get_user_by_username(username)

#     users_with_chat_history = []

#     # Get all users except the logged-in user
#     users = get_users_without_specific_username(username)

#     for u in users:
#         room_id = create_room_id(user["user_id"], u["user_id"])
#         chat_history = get_chat_history_from_db(room_id)

#         if chat_history and chat_history.get("Items"):
#             unread_count = 0

#             # Count unread messages
#             for msg in chat_history["Items"]:
#                 if (
#                     msg.get("receiver") == user["user_id"]
#                     and not msg.get("is_read", False)
#                 ):
#                     unread_count += 1

#             # Sort by the latest message timestamp
#             latest_message = max(
#                 chat_history["Items"], key=lambda x: x["timestamp"]
#             )
#             u["last_activity"] = latest_message["timestamp"]
#             u["unread_count"] = unread_count  # Add unread message count
#             users_with_chat_history.append(u)

#     # Sort users with chat history by the latest activity timestamp
#     users_with_chat_history = sorted(
#         users_with_chat_history, key=lambda x: x["last_activity"], reverse=True
#     )

#     # Handle search query if provided
#     search_query = request.GET.get("search", "").lower()
#     if search_query:
#         users_with_chat_history = [
#             u for u in users_with_chat_history if search_query in u["username"].lower()
#         ]

#     # Prepare the context for the template
#     dic = {
#         "data": users_with_chat_history,  # Only users with chat history
#         "mine": user,
#     }
#     return render(request, "chat.html", dic)


def private_chat(request):
    username = request.session.get("username")
    user = get_user_by_username(username)

    users_with_chat_history = []

    # Get all users except the logged-in user
    users = get_users_without_specific_username(username)

    for u in users:
        room_id = create_room_id(user["user_id"], u["user_id"])
        chat_history = get_chat_history_from_db(room_id)

        print(chat_history)
        if chat_history and chat_history.get("Items"):
            # Check if there are unread messages for this user
            unread = any(
                msg.get("sender") == u["user_id"] and msg.get("is_read") is False
                for msg in chat_history["Items"]
            )

            latest_message = max(chat_history["Items"], key=lambda x: x["timestamp"])
            u["last_activity"] = latest_message["timestamp"]
            u["unread"] = unread  # Add unread status
            print(u["username"], u["unread"])
            users_with_chat_history.append(u)

    # Sort users with chat history by the latest activity timestamp
    users_with_chat_history = sorted(
        users_with_chat_history, key=lambda x: x["last_activity"], reverse=True
    )

    # Handle search query if provided
    search_query = request.GET.get("search", "").lower()
    if search_query:
        users_with_chat_history = [
            u for u in users_with_chat_history if search_query in u["username"].lower()
        ]

    # Prepare the context for the template
    dic = {
        "data": users_with_chat_history,  # Only users with chat history
        "mine": user,
    }
    return render(request, "chat.html", dic)


# change and t &
def create_room_id(uid_a, uid_b):
    """Helper function to create consistent room IDs."""
    ids = sorted([uid_a, uid_b])
    return f"{ids[0]}and{ids[1]}"


# def get_chat_history(request, room_id):
#     # Fetch chat history
#     response = get_chat_history_from_db(room_id)
#     items = response.get("Items", [])

#     # Update each unread message to mark it as read
#     for item in items:
#         if item.get("receiver") == request.session.get("user_id") and not item.get("is_read", False):
#             chat_table.update_item(
#                 Key={
#                     "room_name": room_id,
#                     "timestamp": item["timestamp"],  # Ensure you include the sort key
#                 },
#                 UpdateExpression="SET is_read = :true",
#                 ExpressionAttributeValues={":true": True},
#             )

#     return JsonResponse({"messages": items})


def get_chat_history(request, room_id):
    # Fetch chat history
    response = get_chat_history_from_db(room_id)
    items = response.get("Items", [])

    # Mark unread messages as read
    mark_messages_as_read(request, room_id)

    return JsonResponse({"messages": items})


def group_chat(request):
    username = request.session.get("username")
    user = get_user_by_username(username)
    allUser = get_users_without_specific_username(username)

    data = []
    for i in GroupChatMember.objects.filter(
        uid=user.get("user_id"), status=GroupChatMember.AgreementStatus.COMPLETED
    ):
        data.append({"name": i.name})

    context = {
        "data": data,
        "mine": user,
        "all_users": allUser,
    }
    return render(request, "chatg.html", context)


def create_group_chat(request):
    username = request.session.get("username")
    user = get_user_by_username(username)
    payload = json.loads(request.body.decode())
    allUser = payload.get("allUser")
    roomName = payload.get("roomName")
    existing_group = (GroupChatMember.objects.filter)(name=roomName)

    if (existing_group.exists)():
        return JsonResponse(
            {"code": "400", "message": "Group has already been created!"}
        )

    roomId = (GroupChatMember.objects.create)(
        name=str(roomName),
        uid=user["user_id"],
        status=GroupChatMember.AgreementStatus.COMPLETED,
    )
    (roomId.save)()

    for i in allUser:
        try:
            roomId = (GroupChatMember.objects.create)(
                name=str(roomName),
                uid=i,
                status=GroupChatMember.AgreementStatus.COMPLETED,
            )
            (roomId.save)()
        except Exception as e:
            print(f"Error creating GroupWebSocket for {i}: {e}")
            return JsonResponse({"code": "500", "message": "Database error"})
    dic = {"code": "200", "message": "ok"}
    return JsonResponse(dic, json_dumps_params={"ensure_ascii": False})


def invite_to_group(request):
    payload = json.loads(request.body.decode())
    allUser = payload.get("allUser")
    roomName = payload.get("roomName")

    for i in allUser:
        try:
            roomId = (GroupChatMember.objects.create)(
                name=str(roomName),
                uid=i,
                status=GroupChatMember.AgreementStatus.IN_PROGRESS,
            )
            (roomId.save)()

        except Exception as e:
            print(f"Error creating GroupWebSocket for {i}: {e}")
            return JsonResponse({"code": "500", "message": "Database error"})
    dic = {"code": "200", "message": "ok"}
    return JsonResponse(dic, json_dumps_params={"ensure_ascii": False})


def join_group_chat(request):
    payload = json.loads(request.body.decode())
    userId = payload.get("userId")
    room = payload.get("room")

    group = GroupChatMember.objects.get(uid=userId, name=room)
    group.status = GroupChatMember.AgreementStatus.COMPLETED
    group.save()

    dic = {"code": "200", "message": "ok"}
    return JsonResponse(dic, json_dumps_params={"ensure_ascii": False})


def leave_group_chat(request):
    payload = json.loads(request.body.decode())
    userId = payload.get("userId")
    room = payload.get("room")
    GroupChatMember.objects.get(uid=userId, name=room).delete()

    dic = {"code": "200", "message": "ok"}
    return JsonResponse(dic, json_dumps_params={"ensure_ascii": False})


def get_pending_invitations(request):
    username = request.session.get("username")

    # Retrieve the user ID using the `get_user_by_username` function
    user_id = get_user_by_username(username)["user_id"]

    # Fetch pending invitations for the user from the database
    pending_invitations = GroupChatMember.objects.filter(
        uid=user_id, status=GroupChatMember.AgreementStatus.IN_PROGRESS
    )

    # Convert GroupChatMember objects to a list of dictionaries
    invitation_data = []
    for invitation in pending_invitations:
        invitation_data.append(
            {
                "name": invitation.name,
                "uid": invitation.uid,
                "status": invitation.status,
            }
        )

    # Return the serialized data as JSON response
    dic = {"code": "200", "message": "ok", "data": invitation_data}
    return JsonResponse(dic, json_dumps_params={"ensure_ascii": False})


def search_users(request):
    query = request.GET.get(
        "query", ""
    ).lower()  # Convert to lowercase for case-insensitive search
    username = request.session.get("username")

    try:
        all_users = get_users_without_specific_username(
            username
        )  # Exclude current user
        matching_users = [
            {
                "username": user["username"],
                "user_id": user["user_id"],
            }
            for user in all_users
            if query in user["username"].lower()
        ]
        print(f"Search query: {query}")
        print(f"Matching users: {matching_users}")
        print(f"Matching users after filtering: {matching_users}")
        return JsonResponse(matching_users, safe=False)
    except Exception as e:
        print(f"Error in search_users function: {e}")
        return JsonResponse(
            {"error": "Error occurred while searching users."}, status=500
        )


def mark_messages_as_read(request, room_id):
    user_id = request.session.get("user_id")

    # Fetch unread messages
    unread_messages = chat_table.query(
        KeyConditionExpression=Key("room_name").eq(room_id),
        FilterExpression=Attr("sender").ne(user_id) & Attr("is_read").eq(False),
    )

    # Mark each message as read
    for msg in unread_messages.get("Items", []):
        chat_table.update_item(
            Key={
                "room_name": room_id,
                "timestamp": msg["timestamp"],
            },
            UpdateExpression="SET is_read = :true",
            ExpressionAttributeValues={":true": True},
        )
