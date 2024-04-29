from django.contrib.auth import login, authenticate , logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import JsonResponse
from CVEAlert.chatbot import ask_openai
import requests
import json


from . import forms
from . import models
from firstapp.models import Products, Follow_Product, Affected, CVE , Follow_CVE

status_noti = [
	('telegram', 'Telegram'),
	('gmail', 'Gmail'),
	('all', 'All')
]
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
			create_notify_user = models.NotiUser.objects.create(user=user)
			create_profile.save()
			create_notify_user.save()
		
			return HttpResponseRedirect(reverse('accounts:login'))
		
	return render(request, 'accounts/sign_up.html', {'form': form})

@login_required
def get_logout(request):
	logout(request)
	return HttpResponseRedirect(reverse('app:home'))

@login_required
def profile_detail_view(request):
	try:
		check_user_notifi = models.NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
			status = False
		else:
			status = True
	except:
		status = False
	form = forms.EditProfile()
	profile = models.UserProfile.objects.get(user=request.user)
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	elif request.method == 'POST':
		form = forms.EditProfile(request.POST or None, request.FILES, instance=profile)
		if form.is_valid():
			form.save(commit=True)
			return HttpResponseRedirect(reverse('accounts:profile'))
	
	context= {
		'profile' : profile,
		'form' :form,
		'status': status,
	}

	return render(request,'accounts/profile.html',context=context)





def list_product_view(request):
	try:
		check_user_notifi = models.NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)
		return JsonResponse({'message': message, 'response': response})
	user = request.user
	list_follow = Follow_Product.objects.filter(user=user)
	list_product_ids = [follow.product_id for follow in list_follow]
	list_products = Products.objects.filter(id__in=list_product_ids)
	affected = Affected.objects.filter(product_id__in=list_product_ids)
	affected_con_id = [a.id for a in affected]
	listCVE = CVE.objects.filter(id__in=affected_con_id)
	if 'selected_products_localstorage' in request.POST:
		selected_products_localstorage = json.loads(request.POST.get('selected_products_localstorage'))
		products = Products.objects.filter(name__in=selected_products_localstorage)
		for p in products:
			Follow_Product.objects.filter(user=user, product=p).delete()
			return HttpResponseRedirect(reverse('accounts:list_product'))
		page = 1
	# product_cve


	context = {
		'status': status,
		'list_products': list_products,
		'listCVE': listCVE,
	}
	return render(request, 'accounts/list_product.html',context=context)

#Thêm hàm tại đây!
def list_cve_by_product_view(request):
	try :
		check_user_notifi = models.NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
			status = False
		else:
			status = True
	except:
			status = False

	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	listCVE = []
	if request.method == 'POST':
		if 'search_product' in request.POST:
			search_product = json.loads(request.POST.get('search_product'))
			product = Products.objects.filter(name__contains=search_product)
			product_id = [p.id for p in product]
			affected = Affected.objects.filter(product_id__in=product_id)
			affected_con_id = [a.con_id for a in affected]
			listCVE = CVE.objects.filter(id__in=affected_con_id)
	cve_ids = [cve.id for cve in listCVE]
	affected_cve = Affected.objects.filter(con_id__in=cve_ids)
	products_cve = {}
	for a in affected_cve:
		if a.con_id in products_cve:
			products_cve[a.con_id].append(a.product)
		else:
			products_cve[a.con_id] = [a.product]
	listCVE.affected_cve = affected_cve
	count = listCVE.count()
	context = {
		'listCVE': listCVE,
		'status':status,
		'count' : count,
	}
	return render(request, 'accounts/list_cve_by_product.html', context=context)




@login_required
def change_password_view(request, pk):
    try:
        check_user_notifi = models.NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
            status = False
        else:
            status = True
    except:
        status = False
    mess = ""
    if request.method == 'POST' and 'message' in request.POST:
        message = request.POST['message']
        response = ask_openai(message)
        return JsonResponse({'message': message, 'response': response})
    elif request.method == 'POST' and 'your_news_password1' in request.POST:
        cur_user = models.User.objects.get(pk=pk)
        old_pass = request.POST['old_password']
        new_password = request.POST['your_news_password1']
        new_password_conf = request.POST['your_news_password2']
        
        # New password validation
        if len(new_password) < 8:
            mess = "The password must be at least 8 characters long."

        elif not cur_user.check_password(old_pass):
            mess = 'You entered the wrong old password, please try again!'
        elif new_password != new_password_conf:
            mess = "The passwords you inputted do not match, please try again!"
        else:
            cur_user.set_password(new_password)
            cur_user.save()
            mess = "You have changed your password successfully."
            return HttpResponseRedirect(reverse('accounts:login'))
    context = {
        'mess': mess,
        'status': status,
    }
    return render(request, 'accounts/change_password.html', context=context)


def notification_user_view(request):
	try :
		check_user_notifi = models.NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
			status = False
		else:
			status = True
	except:
			status = False
	form = forms.CreateNotification()
	data_noti = models.NotiUser.objects.get(user_id= request.user.id)
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	elif request.method == 'POST':
		status = request.POST['status']
		email_address = request.POST['email_address']
		token_bot = request.POST['token_bot']
		chat_id = get_chat_id(token_bot)

		data_noti.status = status
		data_noti.email_address = email_address
		data_noti.token_bot = token_bot
		data_noti.chat_id = chat_id
		print(chat_id)
		data_noti.save()
		return HttpResponseRedirect(reverse('accounts:notification'))
	
	context ={
		'user' : request.user,
		'form' : form,
		'data_noti': data_noti,
		'status_noti': status_noti,
		'status' : status
	}

	
	return render(request, 'accounts/notification_user.html',context=context)
  

def get_chat_id(bot_token):
    url_updates = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    response = requests.get(url_updates)
    data = response.json()
    chat_id = None
    if data["ok"]:
        if data["result"]:
            chat_id = data["result"][0]["message"]["chat"]["id"]
    return chat_id
