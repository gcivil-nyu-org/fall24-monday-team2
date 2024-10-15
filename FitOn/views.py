from django.shortcuts import render, redirect
from .dynamodb import create_user, get_user_by_username, get_user_by_email, get_user_by_uid, update_user_password, MockUser, update_reset_request_time, get_last_reset_request_time, get_user, update_user, delete_user_by_username
from .forms import SignUpForm, LoginForm, PasswordResetForm, SetNewPasswordForm, ProfileForm
from .models import PasswordResetRequest
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import logout
from django.contrib import messages
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail, get_connection
from django.core.mail import EmailMultiAlternatives
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode
import os
import uuid, ssl

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
            
            # Query DynamoDB for the user by username
            user = get_user_by_username(username)
            
            if user:
                # Get the hashed password from DynamoDB
                stored_password = user['password']
                user_id = user['user_id']
                
                # Verify the password using Django's check_password
                if check_password(password, stored_password):
                    # Set the session and redirect to the homepage
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
            
            # Hash the password before saving it
            hashed_password = make_password(password)
            
            # Create a unique user ID
            user_id = str(uuid.uuid4())
            
            # Sync data with DynamoDB
            if create_user(user_id, username, email, name, date_of_birth, gender, hashed_password):
                request.session['username'] = username
                request.session['user_id'] = user_id
                return redirect('homepage')
            else:
                form.add_error(None, 'Error creating user in DynamoDB.')
    else:
        form = SignUpForm()  # Return an empty form for the GET request

    return render(request, 'signup.html', {'form': form})  # Ensure form is passed for both GET and POST

def password_reset_request(request):
    countdown = None

    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
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
                        return render(request, 'password_reset_request.html', {'form': form, 'countdown': countdown})
                    
                    # Update reset request time if time has passed
                    update_reset_request_time(user.pk)
                else:
                    update_reset_request_time(user.pk)
                
                # Send reset email
                reset_token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse('password_reset_confirm', args=[user.pk, reset_token])
                )
                subject = 'Password Reset Requested'
                email_context = {
                    'username': user.username,
                    'reset_url': reset_url
                }
                html_message = render_to_string('password_reset_email.html', email_context)

                # Create an unverified SSL context
                unverified_ssl_context = ssl._create_unverified_context()

                # Send the email with the unverified context
                connection = get_connection(ssl_context=unverified_ssl_context)
                send_mail(subject, '', 'fiton.notifications@gmail.com', [email], html_message=html_message, connection=connection)

                return redirect('password_reset_done')
            else:
                error_message = 'The email you entered is not registered with an account.'
    else:
        form = PasswordResetForm()
    return render(request, 'password_reset_request.html', {'form': form, 'countdown': countdown})


def password_reset_confirm(request, user_id, token):
    user = MockUser(get_user_by_uid(user_id))

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetNewPasswordForm(request.POST)
            if form.is_valid():
                new_password = form.cleaned_data['new_password']
                
                # Update the user's password in DynamoDB
                update_user_password(user.pk, new_password)
                return redirect('password_reset_complete')
        else:
            form = SetNewPasswordForm()
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        return render(request, 'password_reset_invalid.html')
    

def password_reset_complete(request):
    return render(request, 'password_reset_complete.html')

def password_reset_done(request):
    return render(request, 'password_reset_done.html')

def upload_profile_picture(request):
    user_id = request.session.get('user_id')  # Get the user ID from the session

    if request.method == 'POST' and request.FILES.get('profile_picture'):
        profile_picture = request.FILES['profile_picture']
        
        # Define the path where the image will be saved
        image_dir = os.path.join(settings.BASE_DIR, 'FitOn/static/images')
        print(image_dir, settings.BASE_DIR)
        # Create the directory if it doesn't exist
        os.makedirs(image_dir, exist_ok=True)

        # Create a custom filename based on user_id
        picture_name = f"{user_id}_profile.jpg"
        image_path = os.path.join(image_dir, picture_name)

        # Save the image to the specified path
        with open(image_path, 'wb+') as destination:
            for chunk in profile_picture.chunks():
                destination.write(chunk)

        # Construct the new image URL
        new_image_url = f"/static/images/{picture_name}"

        # Respond with success
        return JsonResponse({'success': True, 'new_image_url': new_image_url})
    
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
            picture_name = f"{user_id}_profile.jpg"  # Create custom file name
            picture_path = os.path.join(settings.BASE_DIR, 'FitOn/static/images', picture_name)

            # Save the profile picture
            with open(picture_path, 'wb+') as destination:
                for chunk in profile_picture.chunks():
                    destination.write(chunk)

            # Update the user's profile picture URL in DynamoDB
            update_user(user_id, {'profile_picture': {"Value": f'/static/images/{picture_name}'}})

            messages.success(request, "Profile picture updated successfully!")
            return redirect('profile')


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
