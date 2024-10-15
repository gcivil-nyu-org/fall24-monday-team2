from django.shortcuts import render, redirect
from .forms import SignUpForm, LoginForm, ProfileForm
from .dynamodb import create_user, get_user_by_username, get_user, update_user
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse
from django.core.files.storage import FileSystemStorage
import uuid
import os

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
        form = SignUpForm()

    days = list(range(1, 32)) 
    years = list(range(1900, 2025))  
    return render(request, 'signup.html', {'form': form, 'days': days, 'years': years})


def homepage(request):
    # Retrieve the username from the session (if it exists)
    username = request.session.get('username', 'Guest')  # Default to 'Guest' if no username is found
    return render(request, 'home.html', {'username': username})

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
