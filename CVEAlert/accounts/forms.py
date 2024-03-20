from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile

class UserProfileSignUpForm(UserCreationForm):
    name = forms.CharField(max_length=255)
    email = forms.EmailField()
    phone = forms.CharField(max_length=255)

    class Meta:
        model = UserProfile
        fields = ['name', 'email', 'phone', 'password1', 'password2']
