from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile

class UserProfileSignUpForm(UserCreationForm):
	email = forms.EmailField(required=True, label='Email', widget=forms.TextInput(attrs={'placeholder': 'Email'}))
	username = forms.CharField(required=True, label='Username',
							   widget=forms.TextInput(attrs={'placeholder': 'Username'}))
	password1 = forms.CharField(required=True, label='Password',
								widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))
	password2 = forms.CharField(required=True, label='Confirm Password',
								widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}))

	class Meta:
		model = User
		fields = (
			'username',
			'email',
			'password1',
			'password2',
		)
