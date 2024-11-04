from django.shortcuts import render, redirect
from .dynamodb import (
    add_fitness_trainer_application,
    # create_post,
    create_reply,
    create_thread,
    create_user,
    delete_user_by_username,
    # fetch_all_threads,
    fetch_posts_for_thread,
    # fetch_thread,
    get_fitness_trainer_applications,
    get_last_reset_request_time,
    # get_replies,
    # get_thread_details,
    get_user,
    get_user_by_email,
    get_user_by_uid,
    get_user_by_username,
    MockUser,
    update_reset_request_time,
    update_user,
    update_user_password,
    upload_profile_picture,
    fetch_filtered_threads,
    fetch_all_users,
    like_comment,
    report_comment,
    posts_table
)
from .forms import (
    FitnessTrainerApplicationForm,
    LoginForm,
    PasswordResetForm,
    ProfileForm,
    SetNewPasswordForm,
    SignUpForm,
)

# from .models import PasswordResetRequest
from datetime import timedelta, datetime
from django.contrib.auth.hashers import make_password, check_password

# from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout
from django.contrib import messages
from django.conf import settings

# from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail, get_connection

# from django.core.mail import EmailMultiAlternatives
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

# from django.utils.encoding import force_bytes
# from django.utils.html import strip_tags
# from django.utils.http import urlsafe_base64_encode
# import os
import uuid
import ssl
from google_auth_oauthlib.flow import Flow

# from django.contrib.auth.decorators import login_required
from .dynamodb import threads_table, delete_post
import json

# from django.http import HttpResponse

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
    return render(request, "home.html", {"username": username})


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

            # Hash the password before saving it
            hashed_password = make_password(password)

            # Create a unique user ID
            user_id = str(uuid.uuid4())

            # Sync data with DynamoDB
            if create_user(
                user_id, username, email, name, date_of_birth, gender, hashed_password
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

    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            user = get_user_by_email(email)

            if user:
                # Get last reset request time
                last_request_time = get_last_reset_request_time(user.pk)
                if last_request_time:
                    last_request_dt = timezone.datetime.fromisoformat(last_request_time)
                    if timezone.is_naive(last_request_dt):
                        last_request_dt = timezone.make_aware(last_request_dt)

                    time_since_last_request = timezone.now() - last_request_dt

                    if time_since_last_request < timedelta(minutes=2):
                        countdown = 120 - time_since_last_request.seconds
                        return render(
                            request,
                            "password_reset_request.html",
                            {"form": form, "countdown": countdown},
                        )

                    # Update reset request time if time has passed
                    update_reset_request_time(user.pk)
                else:
                    update_reset_request_time(user.pk)

                # Send reset email
                reset_token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse("password_reset_confirm", args=[user.pk, reset_token])
                )
                subject = "Password Reset Requested"
                email_context = {"username": user.username, "reset_url": reset_url}
                html_message = render_to_string(
                    "password_reset_email.html", email_context
                )

                # Create an unverified SSL context
                unverified_ssl_context = ssl._create_unverified_context()

                # Send the email with the unverified context
                connection = get_connection(ssl_context=unverified_ssl_context)
                send_mail(
                    subject,
                    "",
                    "fiton.notifications@gmail.com",
                    [email],
                    html_message=html_message,
                    connection=connection,
                )

                return redirect("password_reset_done")
            # else:
            #     error_message = (
            #         "The email you entered is not registered with an account."
            #     )
    else:
        form = PasswordResetForm()
    return render(
        request, "password_reset_request.html", {"form": form, "countdown": countdown}
    )


def password_reset_confirm(request, user_id, token):
    user = MockUser(get_user_by_uid(user_id))

    if user and default_token_generator.check_token(user, token):
        if request.method == "POST":
            form = SetNewPasswordForm(request.POST)
            if form.is_valid():
                new_password = form.cleaned_data["new_password"]

                # Update the user's password in DynamoDB
                update_user_password(user.pk, new_password)
                return redirect("password_reset_complete")
        else:
            form = SetNewPasswordForm()
        return render(request, "password_reset_confirm.html", {"form": form})
    else:
        return render(request, "password_reset_invalid.html")


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
        return redirect("homepage")

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
    print("inside auth")

    if not credentials or credentials.expired:
        # if settings.DEBUG == True:
        #     flow = Flow.from_client_secrets_file('credentials.json', SCOPES)
        # else:
        print(settings.GOOGLEFIT_CLIENT_CONFIG)
        flow = Flow.from_client_config(settings.GOOGLEFIT_CLIENT_CONFIG, SCOPES)
        flow.redirect_uri = request.build_absolute_uri(reverse("callback_google_fit"))
        print("Redirected URI: ", flow.redirect_uri)
        authorization_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true"
        )
        # Debugging print statements
        print("Authorization URL:", authorization_url)
        print("State:", state)

        request.session["google_fit_state"] = state
        return redirect(authorization_url)
    return redirect("profile")


def callback_google_fit(request):
    user_id = request.session.get("user_id")

    # Fetch user details from DynamoDB
    user = get_user(user_id)
    state = request.session.get("google_fit_state")
    if state:
        # if settings.DEBUG:
        #     flow = Flow.from_client_secrets_file('credentials.json', SCOPES, state=state)
        # else:
        print("inside calback")

        flow = Flow.from_client_config(
            settings.GOOGLEFIT_CLIENT_CONFIG, SCOPES, state=state
        )
        print("flow=", flow)
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
    # Retrieve applications from DynamoDB
    applications = get_fitness_trainer_applications()

    # Render the list of applications
    return render(
        request,
        "fitness_trainer_applications_list.html",
        {"applications": applications},
    )


# -------------------------------
# Forums Functions
# -------------------------------


# def forum_view(request):
#     threads = fetch_all_threads()
#     return render(request, "forums.html", {"threads": threads})


# View to display a single thread with its posts
def thread_detail_view(request, thread_id):
    # Fetch thread details from DynamoDB
    thread = threads_table.get_item(Key={"ThreadID": thread_id}).get("Item")
    posts = fetch_posts_for_thread(thread_id)  # Fetch comments related to the thread

    if not thread:
        return JsonResponse({"status": "error", "message": "Thread not found"}, status=404)

    user_id = request.session.get("username")  # Assuming user is logged in

    if request.method == "POST":
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            # Parse the AJAX request data
            data = json.loads(request.body.decode("utf-8"))
            action = data.get("action")
            post_id = data.get("post_id")

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
                    ExpressionAttributeValues={":l": likes, ":lb": liked_by}
                )
                return JsonResponse({"status": "success", "likes": likes, "liked": user_id in liked_by})

            elif action == "like_comment":
                # Handle like/unlike for a comment
                post = posts_table.get_item(Key={"PostID": post_id, "ThreadID": thread_id}).get("Item")
                if not post:
                    return JsonResponse({"status": "error", "message": "Comment not found"}, status=404)

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
                    ExpressionAttributeValues={":l": likes, ":lb": liked_by}
                )
                return JsonResponse({"status": "success", "likes": likes, "liked": user_id in liked_by})

            elif action == "report_comment":
                # Handle report for a comment (you can define reporting logic here)
                # For simplicity, let's say reporting just returns a success message
                return JsonResponse({"status": "success", "message": "Comment reported successfully!"})

            elif action == "add_reply":
                # Handle adding a reply to a comment
                reply_content = data.get("content", "").strip()
                if not reply_content:
                    return JsonResponse({"status": "error", "message": "Reply content cannot be empty!"})

                # Assuming we have a function `add_reply_to_post`
                reply_id = add_reply_to_post(post_id=post_id, thread_id=thread_id, user_id=user_id, content=reply_content)
                
                # Return success and the reply content with the username
                return JsonResponse({"status": "success", "content": reply_content, "username": user_id, "reply_id": reply_id})
        
        # Handle non-AJAX post submission for creating a new comment
        elif "content" in request.POST:
            # Add a new post to the thread
            new_content = request.POST.get("content").strip()
            if new_content:
                create_reply(thread_id=thread_id, user_id=user_id, content=new_content)

        # Redirect after posting to avoid resubmission on refresh
        return redirect("thread_detail", thread_id=thread_id)

    # Render the thread detail page for a non-AJAX request
    return render(request, "thread_detail.html", {
        "thread": thread,
        "posts": posts,
        "liked": user_id in thread.get("LikedBy", []),
    })




def new_thread_view(request):
    print("PrePost")
    if request.method == "POST":
        print("Post")
        title = request.POST.get("title")
        content = request.POST.get("content")
        user_id = request.session.get("username")  # Assuming the user is logged in

        # Debugging: Add print statements to confirm values
        print(f"Title: {title}, Content: {content}, User: {user_id}")

        if title and content and user_id:
            # Call your DynamoDB function to create a new thread
            create_thread(title=title, user_id=user_id, content=content)

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

            # Log the post_id and thread_id for debugging
            print("post_id: {post_id}, thread_id: {thread_id}")
            print("Hello?")

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
    # Get filter inputs from the request's GET parameters
    username = request.GET.get("username", "")  # Username filter
    thread_type = request.GET.get("type", "all")  # Thread or Reply filter
    start_date = request.GET.get("start_date", "")  # Start date filter
    end_date = request.GET.get("end_date", "")  # End date filter
    search_text = request.GET.get("search", "")  # Search text filter

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

    return render(request, "forums.html", {"threads": threads, "users": users})

def add_reply(request):
    if request.method == "POST" and request.headers.get("x-requested-with") == "XMLHttpRequest":
        data = json.loads(request.body.decode("utf-8"))
        post_id = data.get("post_id")
        content = data.get("content")
        thread_id = data.get("thread_id")
        
        print("Received thread_id:", thread_id)  # Debugging line


        if not post_id or not content:
            return JsonResponse({"status": "error", "message": "Post ID and content are required."}, status=400)
        
        # Get the user info from the session
        user_id = request.session.get("username")
        if not user_id:
            return JsonResponse({"status": "error", "message": "User not authenticated"}, status=403)
        
         # Create the reply data
        reply_data = {
            "ReplyID": str(uuid.uuid4()),  # Unique ID for each reply
            "UserID": user_id,
            "Content": content,
           # "CreatedAt": datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        }

         # Save the reply to DynamoDB by appending it to the 'Replies' list for the post
        try:
            posts_table.update_item(
                Key={
                    "PostID": post_id,
                    "ThreadID": thread_id  # Add ThreadID to match the schema
                },
                UpdateExpression="SET Replies = list_append(if_not_exists(Replies, :empty_list), :reply)",
                ExpressionAttributeValues={
                    ":reply": [reply_data],
                    ":empty_list": []
                },
                ReturnValues="UPDATED_NEW"
            )
        except Exception as e:
            return JsonResponse({"status": "error", "message": f"Failed to save reply: {str(e)}"}, status=500)
        
        # For now, we'll assume successful addition
        return JsonResponse({"status": "success", "content": content, "username": user_id})
    
    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)


def delete_reply(request):
    post_id = request.POST.get('post_id')
    reply_id = request.POST.get('reply_id')

    if not post_id or not reply_id:
        return JsonResponse({"status": "error", "message": "Post ID and Reply ID are required."}, status=400)

     # Retrieve the post and filter out the reply to delete
    try:
        response = posts_table.get_item(Key={"PostID": post_id})
        post = response.get("Item")
        if not post:
            return JsonResponse({"status": "error", "message": "Post not found."}, status=404)

        replies = post.get("Replies", [])
        updated_replies = [reply for reply in replies if reply["ReplyID"] != reply_id]

         # Update the post with the filtered replies list
        posts_table.update_item(
            Key={"PostID": post_id},
            UpdateExpression="SET Replies = :updated_replies",
            ExpressionAttributeValues={":updated_replies": updated_replies}
        )
        return JsonResponse({"status": "success"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": "Failed to delete reply: {str(e)}"}, status=500)


def delete_thread(request):
    if request.method == "POST" and request.headers.get("x-requested-with") == "XMLHttpRequest":
        data = json.loads(request.body.decode("utf-8"))
        thread_id = data.get("thread_id")

        if not thread_id:
            return JsonResponse({"status": "error", "message": "Thread ID is required."}, status=400)

        try:
            # Perform the deletion from DynamoDB
            threads_table.delete_item(Key={"ThreadID": thread_id})
            return JsonResponse({"status": "success", "message": "Thread deleted successfully."})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)
    return JsonResponse({"status": "error", "message": "Invalid request method."}, status=400)