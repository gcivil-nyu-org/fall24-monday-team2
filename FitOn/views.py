from django.shortcuts import render, redirect
from .forms import SignUpForm, LoginForm, PasswordResetForm, SetNewPasswordForm
from .dynamodb import create_user, get_user_by_username, get_user_by_email, get_user_by_uid, update_user_password, MockUser, update_reset_request_time, get_last_reset_request_time
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail, get_connection
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import strip_tags
from django.utils import timezone
from datetime import timedelta
from .models import PasswordResetRequest
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
                
                # Verify the password using Django's check_password
                if check_password(password, stored_password):
                    # Set the session and redirect to the homepage
                    request.session['username'] = username
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
                return redirect('homepage')
            else:
                form.add_error(None, 'Error creating user in DynamoDB.')
    else:
        form = SignUpForm()  # Return an empty form for the GET request

    return render(request, 'signup.html', {'form': form})  # Ensure form is passed for both GET and POST


import ssl
from django.core.mail import get_connection

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
