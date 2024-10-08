from django import forms

class SignUpForm(forms.Form):
    username = forms.CharField(max_length=100)
    email = forms.EmailField()
    name = forms.CharField(max_length=100)
