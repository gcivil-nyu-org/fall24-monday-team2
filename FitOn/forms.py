from django import forms
from django.core.exceptions import ValidationError
import datetime
from .dynamodb import get_user_by_username
import re


GENDER_OPTIONS = [
    ("", "Choose gender"),
    ("M", "Male"),
    ("F", "Female"),
    ("O", "Other"),
    ("PNTS", "Prefer not to say"),
]

# Country codes for dropdown
COUNTRY_CODES = [
    ("", ""),
    ("+1", "US/Canada (+1)"),
    ("+44", "UK (+44)"),
    ("+91", "India (+91)"),
    # Add more country codes as needed
]


class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, label="Username")
    password = forms.CharField(
        widget=forms.PasswordInput(),
        label="Password",
        required=True,
        error_messages={"required": "Please enter a valid password."},
    )


class SignUpForm(forms.Form):
    username = forms.CharField(max_length=20, label="Username")
    email = forms.EmailField(label="Email")
    name = forms.CharField(max_length=50, label="Full Name")
    date_of_birth = forms.DateField(
        widget=forms.SelectDateWidget(
            years=range(1900, datetime.date.today().year + 1)
        ),
        label="Date of Birth",
    )
    GENDER_CHOICES = GENDER_OPTIONS

    # Change the widget from RadioSelect to Select for the dropdown
    gender = forms.ChoiceField(
        choices=GENDER_CHOICES, widget=forms.Select, label="Gender"
    )

    height = forms.IntegerField(
        label="Height", min_value=50, max_value=300, initial=170
    )
    weight = forms.IntegerField(label="Weight", min_value=20, max_value=500, initial=70)

    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(), label="Confirm Password"
    )

    def clean_username(self):
        username = self.cleaned_data.get("username")

        # Check if username exceeds 20 characters
        if len(username) > 20:
            raise ValidationError("Username cannot exceed 20 characters.")

        # Ensure username contains only alphanumeric characters (letters, numbers, and no special characters)
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise ValidationError(
                "Username can only contain letters, numbers, and underscores."
            )

        # Query DynamoDB to check if the username already exists
        if get_user_by_username(username):
            raise ValidationError(
                "This username is already taken. Please choose another."
            )

        return username

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
    new_password = forms.CharField(
        widget=forms.PasswordInput, label="New Password", max_length=100
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput, label="Confirm Password", max_length=100
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


class ProfileForm(forms.Form):
    name = forms.CharField(max_length=100, required=True)
    date_of_birth = forms.CharField(
        required=True, widget=forms.TextInput(attrs={"type": "date"})
    )
    email = forms.EmailField(
        required=True, widget=forms.EmailInput(attrs={"readonly": "readonly"})
    )
    gender = forms.ChoiceField(widget=forms.Select, choices=GENDER_OPTIONS)

    # Add country code field
    country_code = forms.ChoiceField(
        choices=COUNTRY_CODES, required=False, label="Country Code"
    )
    phone_number = forms.CharField(max_length=15, required=False)

    address = forms.CharField(widget=forms.Textarea, required=False)
    bio = forms.CharField(widget=forms.Textarea, required=False)

    height = forms.IntegerField(
        label="Height (in cm)",
        min_value=50,
        max_value=300,
        required=False,
        widget=forms.NumberInput(),
    )
    weight = forms.IntegerField(
        label="Weight (in kg)",
        min_value=20,
        max_value=500,
        required=False,
        widget=forms.NumberInput(),
    )

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get("phone_number")
        if phone_number and not phone_number.isdigit():
            raise forms.ValidationError("Phone number should contain only digits.")
        return phone_number

    def clean(self):
        cleaned_data = super().clean()
        country_code = cleaned_data.get("country_code")
        phone_number = cleaned_data.get("phone_number")

        # Validate country_code and phone_number
        if (country_code and not phone_number) or (not country_code and phone_number):
            # Add an error linked to the country_code field
            self.add_error(
                "phone_number",
                "Both country code and phone number must be provided together",
            )
            self.add_error(
                "country_code",
                "Both country code and phone number must be provided together",
            )

        return cleaned_data


# Validation function for PDF files
def validate_file_extension(value):
    if not value.name.endswith(".pdf"):
        raise ValidationError("Only PDF files are allowed.")


# Form for Fitness Trainer Application
class FitnessTrainerApplicationForm(forms.Form):
    past_experience_trainer = forms.CharField(
        max_length=500,
        required=True,
        widget=forms.Textarea(
            attrs={"placeholder": "Describe your past experience..."}
        ),
    )

    past_experience_dietician = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(
            attrs={"placeholder": "Describe your past experience..."}
        ),
    )

    resume = forms.FileField(validators=[validate_file_extension], required=True)

    certifications = forms.FileField(
        validators=[validate_file_extension], required=False
    )

    reference_name = forms.CharField(max_length=100, required=True)

    reference_contact = forms.CharField(max_length=100, required=True)
