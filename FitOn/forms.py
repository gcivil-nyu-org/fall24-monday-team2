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
        ('', 'Choose gender'),
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
        ('PNTS', 'Prefer not to say'),
    ]
    
    # Change the widget from RadioSelect to Select for the dropdown
    gender = forms.ChoiceField(choices=GENDER_CHOICES, widget=forms.Select, label="Gender")
    
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        
        return cleaned_data
    

class PasswordResetForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=100)

class SetNewPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput, label="New Password", max_length=100)
    confirm_password = forms.CharField(widget=forms.PasswordInput, label="Confirm Password", max_length=100)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned_data
