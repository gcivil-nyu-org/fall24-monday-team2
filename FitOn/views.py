from django.shortcuts import render, redirect
from .forms import SignUpForm, LoginForm, PasswordResetForm, SetNewPasswordForm
from .dynamodb import create_user, get_user_by_username, get_user_by_email, get_user_by_uid, update_user_password, MockUser
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import strip_tags

import uuid

    
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
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})

def homepage(request):
    username = request.session.get('username', 'Guest')
    return render(request, 'home.html', {'username': username})

def password_reset_request(request):
    error_message = None  # Add an error message variable
    
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

                # Send reset email
                subject = 'Password Reset Requested'
                message = f'Hi {user.username},\n\nClick the link below to reset your password:\n{reset_url}'
                send_mail(subject, message, 'admin@yourdomain.com', [email])

                # Redirect to reset done page
                return redirect('password_reset_done')
            else:
                error_message = 'The email you entered is not registered with an account.'
    else:
        form = PasswordResetForm()

    return render(request, 'password_reset_request.html', {'form': form, 'error_message': error_message})

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