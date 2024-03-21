from django.contrib.auth import login, authenticate , logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse




from . import forms
from . import models

# Create your views here.

def get_login(request):
	form = AuthenticationForm()
	msg = ""
	
	if request.method == 'POST':
		form = AuthenticationForm(data=request.POST)
		if form.is_valid():
			username = form.cleaned_data.get('username')
			password = form.cleaned_data.get('password')

			user = authenticate(username=username, password=password)
			if user is not None:
				login(request, user)
				return HttpResponseRedirect(reverse('app:home'))
			else:
				msg = "Your account name or password is incorrect!"
		else:
			msg = "Your account name or password is incorrect!"
			
	context = {
		'form': form,
		'msg': msg
	}
	return render(request, 'accounts/login.html', context=context)


def get_sign_up(request):
	form = forms.UserProfileSignUpForm()
	
	if request.method == 'POST':
		form = forms.UserProfileSignUpForm(request.POST)
		if form.is_valid():
			user = form.save()
			create_profile = models.UserProfile.objects.create(user=user)
			create_profile.save()
			return HttpResponseRedirect(reverse('accounts:login'))
		
	return render(request, 'accounts/sign_up.html', {'form': form})

@login_required
def get_logout(request):
	logout(request)
	return HttpResponseRedirect(reverse('app:home'))