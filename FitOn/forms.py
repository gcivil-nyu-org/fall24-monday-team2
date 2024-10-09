from django import forms
from django.core.exceptions import ValidationError
import datetime

class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, label="Username")
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")


class SignUpForm(forms.Form):
    username = forms.CharField(max_length=100, label="Username")
    email = forms.EmailField(label="Email")
    name = forms.CharField(max_length=100, label="Full Name")
    date_of_birth = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, datetime.date.today().year+1)), label="Date of Birth")
    
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    gender = forms.ChoiceField(choices=GENDER_CHOICES, widget=forms.RadioSelect, label="Gender")
    
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        
        return cleaned_data
