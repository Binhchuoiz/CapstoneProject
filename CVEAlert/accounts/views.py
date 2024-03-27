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
			return HttpResponseRedirect(reverse('app:home'))
		
	return render(request, 'accounts/sign_up.html', {'form': form})

@login_required
def get_logout(request):
	logout(request)
	return HttpResponseRedirect(reverse('app:home'))

@login_required
def profile_detail_view(request):
	profile = models.UserProfile.objects.get(user=request.user)
	form = forms.EditProfile()
	profile = models.UserProfile.objects.get(user=request.user)
	if request.method == 'POST':
		form = forms.EditProfile(request.POST or None, request.FILES, instance=profile)
		if form.is_valid():
			form.save(commit=True)
			return HttpResponseRedirect(reverse('accounts:profile'))
	
	context= {
		'profile' : profile,
		'form' :form,
	}

	return render(request,'accounts/profile.html',context=context)





def list_affect_view(request):
	return render(request, 'accounts/list_affect.html')

@login_required
def change_password_view(request,pk):
	mess = ""
	if request.method == 'POST' and 'your_new_password1' in request.POST:
		cur_user = models.User.objects.get(pk=pk)
		old_pass = request.POST['old_password']
		new_pass = request.POST['new_pass']
		new_pass_conf = request.POST['new pass1']
		print("--check", cur_user.check_password(old_pass))
		if not cur_user.check_password(old_pass):
			mess = "wrong old password , please try again!"
		elif new_pass != new_pass_conf :
			mess = "new password u input is not identical , please try again!"
		else:
			cur_user.set_password(new_pass)
			cur_user.save
			mess = "u have changed password succesfully"
			return HttpResponseRedirect(reverse('app:home'))
		
	context = {
		'mess' : mess
	}
	return render(request, 'accounts/change_password.html', context=context)

def notification_user_view(request):
	return render(request, 'accounts/notification_user.html')