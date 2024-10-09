from django.shortcuts import render, redirect
from .forms import SignUpForm, LoginForm
from .dynamodb import create_user, get_user_by_username
from django.contrib.auth.hashers import make_password, check_password
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
            # Delete this line later
            print(form.cleaned_data)  
            
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
            if create_user(user_id, email, name, date_of_birth, gender, hashed_password):
                request.session['username'] = username
                return redirect('homepage')
            else:
                form.add_error(None, 'Error creating user in DynamoDB.')
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})


def homepage(request):
    # Retrieve the username from the session (if it exists)
    username = request.session.get('username', 'Guest')  # Default to 'Guest' if no username is found
    return render(request, 'home.html', {'username': username})
