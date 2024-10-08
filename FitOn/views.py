from django.shortcuts import render, redirect
from .forms import SignUpForm
from .dynamodb import create_user
import uuid

from django.shortcuts import render, redirect
from .forms import SignUpForm
from .dynamodb import create_user
import uuid

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            name = form.cleaned_data['name']
            
            # Create a unique user ID
            user_id = str(uuid.uuid4())
            
            # Sync data with DynamoDB
            if create_user(user_id, email, name):
                # Store the username in the session to access it in homepage
                request.session['username'] = username
                return redirect('homepage')  # Redirect to the homepage
            else:
                form.add_error(None, 'Error creating user in DynamoDB.')
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})


def homepage(request):
    # Retrieve the username from the session (if it exists)
    username = request.session.get('username', 'Guest')  # Default to 'Guest' if no username is found
    return render(request, 'home.html', {'username': username})
