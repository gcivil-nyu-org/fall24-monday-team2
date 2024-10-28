from django.shortcuts import render, redirect
from .dynamodb import (
    add_fitness_trainer_application, create_post, create_reply,
    create_thread, create_user, delete_user_by_username,
    fetch_all_threads, fetch_posts_for_thread, fetch_thread,
    get_fitness_trainer_applications, get_last_reset_request_time,
    get_replies, get_thread_details, get_user, get_user_by_email,
    get_user_by_uid, get_user_by_username, MockUser,
    update_reset_request_time, update_user, update_user_password,
    upload_profile_picture,
)
from .forms import (
    FitnessTrainerApplicationForm, LoginForm, PasswordResetForm,
    ProfileForm, SetNewPasswordForm, SignUpForm,
)
from .models import PasswordResetRequest
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail
from django.core import mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
import os
import uuid

def homepage(request):
    username = request.session.get('username', 'Guest')
    return render(request, 'home.html', {'username': username})

def login(request):
    error_message = None
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = get_user_by_username(username)
            if user:
                stored_password = user['password']
                user_id = user['user_id']
                if check_password(password, stored_password):
                    request.session['username'] = username
                    request.session['user_id'] = user_id
                    return redirect('homepage')
                else:
                    error_message = 'Invalid password. Please try again.'
            else:
                error_message = 'User does not exist.'
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form, 'error_message': error_message})

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            name = form.cleaned_data['name']
            date_of_birth = form.cleaned_data['date_of_birth']
            gender = form.cleaned_data['gender']
            password = form.cleaned_data['password']
            hashed_password = make_password(password)
            user_id = str(uuid.uuid4())
            if create_user(user_id, username, email, name, date_of_birth, gender, hashed_password):
                request.session['username'] = username
                request.session['user_id'] = user_id
                return redirect('homepage')
            else:
                form.add_error(None, 'Error creating user in DynamoDB.')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})

def password_reset_request(request):
    error_message = None

    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = get_user_by_email(email)

            if user:
                reset_token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse('password_reset_confirm', args=[user.pk, reset_token])
                )

                subject = 'Password Reset Requested'
                email_context = {'username': user.username, 'reset_url': reset_url}
                html_message = render_to_string('password_reset_email.html', email_context)

                try:
                    send_mail(
                        subject, '', 'fiton.notifications@gmail.com', [email],
                        html_message=html_message
                    )
                except Exception as e:
                    error_message = f"There was an issue sending the email: {e}"
                    return render(request, 'password_reset_request.html', {
                        'form': form, 'error_message': error_message
                    })

                update_reset_request_time(user.pk)
                return redirect('password_reset_done')
            else:
                error_message = 'The email you entered is not registered with an account.'

    else:
        form = PasswordResetForm()

    return render(request, 'password_reset_request.html', {
        'form': form, 'error_message': error_message
    })

def password_reset_confirm(request, user_id, token):
    try:
        user_id = force_str(urlsafe_base64_decode(user_id))  # Decode the user_id
        user = get_user_by_uid(user_id)  # Fetch user by UID
        print(f"[DEBUG] Decoded User ID: {user_id}, Fetched User: {user}")
    except Exception as e:
        print(f"[DEBUG] Error decoding UID: {e}")
        user = None

    if user:
        is_token_valid = default_token_generator.check_token(user, token)
        print(f"[DEBUG] Token Valid: {is_token_valid}")

        if is_token_valid:
            if request.method == 'POST':
                form = SetNewPasswordForm(request.POST)
                if form.is_valid():
                    new_password = form.cleaned_data['new_password']
                    confirm_password = form.cleaned_data['confirm_password']

                    if new_password == confirm_password:
                        update_user_password(user.pk, new_password)
                        messages.success(request, 'Your password has been successfully reset.')
                        return redirect('password_reset_complete')
                    else:
                        form.add_error('confirm_password', 'Passwords do not match.')
            else:
                form = SetNewPasswordForm()

            return render(request, 'password_reset_confirm.html', {'form': form})

    print("[DEBUG] Invalid user or token")
    return render(request, 'password_reset_invalid.html')

def password_reset_complete(request):
    return render(request, 'password_reset_complete.html')

def password_reset_done(request):
    return render(request, 'password_reset_done.html')


def upload_profile_picture_view(request):
    user_id = request.session.get('user_id')  # Get the user ID from the session

    if request.method == 'POST' and request.FILES.get('profile_picture'):
        profile_picture = request.FILES['profile_picture']

        # Upload to S3 and get the URL
        new_image_url = upload_profile_picture(user_id, profile_picture)

        if new_image_url:
            return JsonResponse({'success': True, 'new_image_url': new_image_url})
        else:
            return JsonResponse({'success': False, 'message': 'Failed to upload image to S3'})

    return JsonResponse({'success': False, 'message': 'No file uploaded'})

def profile_view(request):
    user_id = request.session.get('user_id')

    # Fetch user details from DynamoDB
    user = get_user(user_id)

    if not user:
        messages.error(request, "User not found.")
        return redirect('homepage')

    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.FILES:
            profile_picture = request.FILES['profile_picture']
            image_url = upload_profile_picture(user_id, profile_picture)

            if image_url:
                # Update the user's profile picture URL in DynamoDB
                update_user(user_id, {'profile_picture': {"Value": image_url}})
                messages.success(request, "Profile picture updated successfully!")
                return redirect('profile')
            else:
                messages.error(request, "Failed to upload profile picture.")

        # Handling other profile updates
        form = ProfileForm(request.POST)
        if form.is_valid():
            # Prepare data to be updated
            update_data = {
                'name': {"Value": form.cleaned_data['name']},
                'date_of_birth': {"Value": form.cleaned_data['date_of_birth']},
                'gender': {"Value": form.cleaned_data['gender']},
                'bio': {"Value": form.cleaned_data['bio']},
                'address': {"Value": form.cleaned_data['address']},
            }

            # Only add phone number and country code if provided
            country_code = form.cleaned_data['country_code']
            phone_number = form.cleaned_data['phone_number']
            
            if country_code:  # If country code is provided, add it to update_data
                update_data['country_code'] = {"Value": country_code}
            if phone_number:  # If phone number is provided, add it to update_data
                update_data['phone_number'] = {"Value": phone_number}

            update_user(user_id, update_data)
            messages.success(request, "Profile updated successfully!")
            return redirect('profile')
        else:
            messages.error(request, "Please correct the errors below")
    else:
        form = ProfileForm(initial={
            'name': user.get('name', ''),
            'date_of_birth': user.get('date_of_birth', ''),
            'email': user.get('email', ''),
            'gender': user.get('gender', ''),
            'phone_number': user.get('phone_number', ''),
            'address': user.get('address', ''),
            'bio': user.get('bio', ''),
            'country_code': user.get('country_code', '')  # Default country code
        })

    return render(request, 'profile.html', {'form': form, 'user': user})


def deactivate_account(request):
    # This simply shows the confirmation page
    return render(request, 'deactivate.html')

def confirm_deactivation(request):
    if request.method == 'POST':
        username = request.session.get('username')
        
        if username:
            # Delete the user from DynamoDB
            if delete_user_by_username(username):
                # Log the user out and redirect to the homepage
                logout(request)
                return redirect('homepage')  # Redirect to homepage after deactivation
            else:
                return render(request, 'deactivate.html', {'error_message': 'Error deleting the account.'})
        else:
            # Redirect to login if there's no username in session
            return redirect('login')
    else:
        # Redirect to the deactivate page if the request method is not POST
        return redirect('deactivate_account')

def fitness_trainer_application_view(request):
    user_id = request.session.get('user_id')
    if request.method == 'POST':
        form = FitnessTrainerApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            past_experience_trainer = form.cleaned_data.get('past_experience_trainer')
            past_experience_dietician = form.cleaned_data.get('past_experience_dietician')
            resume = request.FILES['resume']
            certifications = request.FILES.get('certifications')
            reference_name = form.cleaned_data.get('reference_name')
            reference_contact = form.cleaned_data.get('reference_contact')

            # Call the DynamoDB function, making sure all names match
            add_fitness_trainer_application(
                user_id=user_id,
                past_experience_trainer=past_experience_trainer,
                past_experience_dietician=past_experience_dietician,
                resume=resume,
                certifications=certifications,
                reference_name=reference_name,
                reference_contact=reference_contact
            )

            # Notify user and redirect
            messages.success(request, "Your application has been submitted successfully!")
            return redirect('profile')

    else:
        form = FitnessTrainerApplicationForm()

    return render(request, 'fitness_trainer_application.html', {'form': form})


def fitness_trainer_applications_list_view(request):
    # Retrieve applications from DynamoDB
    applications = get_fitness_trainer_applications()

    # Render the list of applications
    return render(request, 'fitness_trainer_applications_list.html', {'applications': applications})








# -------------------------------
# Forums Functions
# -------------------------------

def forum_view(request):
    threads = fetch_all_threads()
    return render(request, 'forums.html', {'threads': threads})

# View to display a single thread with its posts
def thread_detail_view(request, thread_id):
    # Fetch thread details from DynamoDB
    thread = threads_table.get_item(Key={'ThreadID': thread_id}).get('Item')
    posts = fetch_posts_for_thread(thread_id)  # Fetch replies related to the thread

    if not thread:
        return JsonResponse({'status': 'error', 'message': 'Thread not found'}, status=404)

    user_id = request.session.get('username')  # Assuming user is logged in

    if request.method == 'POST':
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            # Get the list of users who have liked the thread
            liked_by = thread.get('LikedBy', [])

            if user_id in liked_by:
                # If user has already liked the post, "unlike" (remove the like)
                likes = max(0, thread.get('Likes', 0) - 1)  # Ensure likes never go below 0
                liked_by.remove(user_id)  # Remove the user from the LikedBy list
            else:
                # If user hasn't liked the post, add a like
                likes = thread.get('Likes', 0) + 1
                liked_by.append(user_id)  # Add the current user to the LikedBy list

            # Update the thread with the new like count and LikedBy list
            threads_table.update_item(
                Key={'ThreadID': thread_id},
                UpdateExpression="set Likes=:l, LikedBy=:lb",
                ExpressionAttributeValues={
                    ':l': likes,
                    ':lb': liked_by
                }
            )
            return JsonResponse({'status': 'success', 'likes': likes, 'liked': user_id in liked_by})

        else:
            # Handle reply submission (non-AJAX form submission)
            content = request.POST.get('content')

            if content and user_id:
                create_reply(thread_id=thread_id, user_id=user_id, content=content)
                return redirect('thread_detail', thread_id=thread_id)

    return render(request, 'thread_detail.html', {'thread': thread, 'posts': posts, 'liked': user_id in thread.get('LikedBy', [])})


def new_thread_view(request):
    print("PrePost")
    if request.method == 'POST':
        print("Post")
        title = request.POST.get('title')
        content = request.POST.get('content')
        user_id = request.session.get('username')  # Assuming the user is logged in

        # Debugging: Add print statements to confirm values
        print(f"Title: {title}, Content: {content}, User: {user_id}")

        if title and content and user_id:
            # Call your DynamoDB function to create a new thread
            create_thread(title=title, user_id=user_id, content=content)

            # Redirect to the forums page after successfully creating the thread
            return redirect('forum')
        else:
            # If something's missing, return the form with an error message
            return render(request, 'new_thread.html', {'error': 'All fields are required.'})
    
    # If the request method is GET, simply show the form
    return render(request, 'new_thread.html')


def delete_post_view(request):
    
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            
            data = json.loads(request.body.decode('utf-8'))
            post_id = data.get('post_id')
            thread_id = data.get('thread_id')  # Make sure you're getting thread_id too

             # Log the post_id and thread_id for debugging
            print("post_id: {post_id}, thread_id: {thread_id}")
            print("Hello?")
            
            if not post_id or not thread_id:
                return JsonResponse({'status': 'error', 'message': 'Post or Thread ID missing'}, status=400)

            # Call the delete_post function to delete from DynamoDB
            if delete_post(post_id, thread_id):
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Failed to delete post'}, status=500)

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

