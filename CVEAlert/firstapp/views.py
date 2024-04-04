from django.shortcuts import render, HttpResponseRedirect, redirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE , Affected , References , Metric , CvssV31 , Products , Vendors , Descriptions , Solutions , Products_Versions , Follow_Affected 
from accounts.models import NotiUser
from .forms import CVEform,AffectedForm
from django.db.models import F, DateTimeField , ExpressionWrapper
from django.db.models.functions import Cast
from django.http import JsonResponse
from CVEAlert.chatbot import ask_openai
# Create your views here.
def get_home(request):
    listCVE = CVE.objects.all().order_by('-date_publish')[:3] 
    cve_ids = [cve.id for cve in listCVE] 
    affected = Affected.objects.filter(con_id__in=cve_ids) 
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]
    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status:
            status = False
        else:
            status = True
    except:
            status = False
    if request.method == 'POST' and 'message' in request.POST:
        message = request.POST['message']
        response = ask_openai(message)
        return JsonResponse({'message': message, 'response': response})
    elif request.method == 'POST': 
        id_cve= request.POST['id_cve']
        listCVE = CVE.objects.filter(cve_id__contains=id_cve)[:12]
    
    context = {
        'listCVE': listCVE,
        'products': products,
        'vendors': vendors,
        'affected': affected,
		'status': status,
    }
    return render(request, 'home.html', context=context)

def get_list_CVE(request, page):
    listCVE = CVE.objects.all().order_by('date_publish')
    year = CVE.objects.values_list('year', flat=True)
    unique_Year = set(year)
    unique_year_List = list(unique_Year)
    unique_year_List.sort()
    
    selected_year = None
    search_focus = None
    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status:
            status = False
        else:
            status = True
    except:
            status = False
    if request.method == 'POST' and 'message' in request.POST:
        message = request.POST['message']
        response = ask_openai(message)
        return JsonResponse({'message': message, 'response': response})
    elif request.method == 'POST':
        selected_years = request.POST.getlist('filter_year')
        if selected_years:
            selected_year = selected_years[0]  
            listCVE = CVE.objects.filter(year__in=selected_years)
            page = 1
        if 'search_focus' in request.POST:
            search_focus = request.POST['search_focus']
            listCVE = listCVE.filter(cve_id__contains=search_focus)
            page = 1
    else:
        search_focus = request.GET.get('search_focus', None)
        selected_year = request.GET.get('filter_year', None)
        if selected_year:
            listCVE = listCVE.filter(year=selected_year)
        if search_focus:
            listCVE = listCVE.filter(cve_id__contains=search_focus)
        search_focus = request.GET.get('search_focus', None)
    per_page = request.GET.get("per_page", 10)
    paginator = Paginator(listCVE, per_page)
    page_obj = paginator.get_page(page)

    cve_ids = [cve.id for cve in page_obj]

    affected = Affected.objects.filter(con_id__in=cve_ids)
    products = {}
    vendors = {}
    for a in affected:
        if a.con_id in products:
            products[a.con_id].append(a.product)
            vendors[a.con_id].append(a.vendor)
        else:
            products[a.con_id] = [a.product]
            vendors[a.con_id] = [a.vendor]
    page_obj.affected = affected
    if request.method == 'POST' and 'search_focus' in request.POST and 'products' in request.POST:
             product_Name = request.POST['search_focus']
             affected = Affected.objects.filter(product__in = product_Name)
    elif request.method == 'POST' and 'search_focus' in request.POST and 'vendors' in request.POST:
             vendors_Name = request.POST['search_focus']
             affected = Affected.objects.filter(vendor__in=vendors_Name)   
    page_obj.affected = affected
    # print(unique_year_List)
    context = {
        "page": {
            'prev': page_obj.number - 1 if page_obj.number - 1 > 0 else 1,
            'current': page_obj.number,
            'next': page_obj.number + 1 if page_obj.number + 1 < paginator.num_pages else paginator.num_pages,
        },
        'len_page': paginator.num_pages,
        'paginator': paginator,
        'page_obj': page_obj,
        'products': products,
        'vendors': vendors,
        'affected': affected,
        'unique_year': unique_year_List,
        'selected_year': selected_year,
        'search_focus': search_focus,
		'status': status,
    }

    # print(listCVE)
    return render(request, 'firstapp/list_cves.html', context=context)   





def get_list_Products(request, page, letter=None):
    if letter:
        list_products = Products.objects.filter(name__istartswith=letter).order_by('name')
    else:
        list_products = Products.objects.all().order_by('name')
    per_page = request.GET.get("per_page", 10)
    paginator = Paginator(list_products, per_page)
    page_obj = paginator.get_page(page)
    
    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status:
            status = False
        else:
            status = True
    except:
        status = False
    
    
    if request.method == 'POST':
        if 'message' in request.POST:
            message = request.POST['message']
            response = ask_openai(message)
            return JsonResponse({'message': message, 'response': response})
        elif 'selected_products' in request.POST:
            selected_products = request.POST.getlist('selected_products')
            user = request.user
            affected = Affected.objects.filter(product_id__in=selected_products)
            for a in affected:
                Follow_Affected.objects.get_or_create(user=user, affected=affected)

    
    context = {
        "page": {
            'prev': page_obj.number - 1 if page_obj.number - 1 > 0 else 1,
            'current': page_obj.number,
            'next': page_obj.number + 1 if page_obj.number + 1 < paginator.num_pages else paginator.num_pages,
        },
        'len_page': paginator.num_pages,
        'paginator': paginator,
        'page_obj': page_obj,
        'list_products': list_products,
        'status': status,
    }
    return render(request, 'firstapp/list_products.html', context=context)


def get_detail_cves(request, pk):
    detail_cve = CVE.objects.get(pk=pk)
    affected = Affected.objects.filter(con_id=detail_cve.id)
    products = [a.product for a in affected]
    products_versions = Products_Versions.objects.filter(product__in=products)
    versions = [p.version for p in products_versions]
    vendors = [a.vendor for a in affected]
     
    try :
        metric = Metric.objects.filter(con_id=detail_cve.id)
    except :
        metric = None
    cvssv31 = [m.cvssv31 for m in metric]
     
    try:
        solutions = Solutions.objects.get(pk=pk)
    except Solutions.DoesNotExist:
        solutions = None

    try:
        descriptions = Descriptions.objects.get(pk=pk)
    except Descriptions.DoesNotExist:
        descriptions = None
    try:
        refrences = References.objects.filter(con_id=pk)
    except References.DoesNotExist:
         refrences = None

    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status:
            status = False
        else:
            status = True
    except:
            status = False
    if request.method == 'POST' and 'message' in request.POST:
        message = request.POST['message']
        response = ask_openai(message)
        return JsonResponse({'message': message, 'response': response})
       
    context = {
         'detail_cve': detail_cve,
         'products' : products,
         'versions' : versions,
         'vendors' : vendors,
         'affected': affected,
         'products_versions' : products_versions,
         'metric' : metric,
         'solutions' : solutions,
         'descriptions' : descriptions,
         'refrences' : refrences,
         'cvssv31' : cvssv31,
		 	'status': status,

    }

    return render(request, 'firstapp/detail_cve.html' , context=context)

def create_cve_view(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	form = CVEform()
	# bot chat
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	elif request.method == 'POST':
		form = AffectedForm(request.POST or None, request.FILES)
		if form.is_valid():
			data = form.save(commit=True)
			return HttpResponseRedirect(reverse('app:home'))

	context = {
		'form': form,
		'status': status
	}
	return render(request, 'firstapp/create_cves.html', context=context)


def create_affect_view(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	form = AffectedForm()
	# bot chat
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	elif request.method == 'POST':
		form = AffectedForm(request.POST)
		if form.is_valid():
			data = form.save(commit=True)
			return HttpResponseRedirect(reverse('app:home'))

	context = {
		'form': form,
		'status': status
	}
	return render(request, 'firstapp/create_affected.html', context=context)


def get_tele_notifi(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'telegram_notifi.html', {'status': status})


def get_gmail_notifi(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	data_noti = NotiUser.objects.get(user_id=request.user.id)
	msg = ""
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	elif request.method == 'POST':
		status = 'gmail'
		email_address = request.POST['email_notification']
		data_noti.status = status
		data_noti.email_address = email_address
		data_noti.save()
		msg = "You have successfully set up Gmail notifications"

	context = {
		'msg': msg,
		'status': status,
	}
	return render(request, 'gmail_notifi.html', context=context)


def get_about(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/about.html', {'status': status})


def get_list_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/list_definations.html', {'status': status})


def get_cve_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/cve.html', {'status': status})

def get_cvss_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/cvss.html', {'status': status})

def get_cvss_compare(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/comparecvss.html', {'status': status})

def get_base_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/base.html', {'status': status})


def get_temporal_definations(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/temporal.html', {'status': status})

def get_environmental_definations(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/environmental.html', {'status': status})

def get_difference_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/difference.html', {'status': status})

def get_type_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Definations/product_and_vendor.html', {'status': status})

def get_list_statistic(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/list_statistics.html', {'status': status})

def get_cve_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Statistics/cve_statistic.html', {'status': status})

def get_risk_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Statistics/risk.html', {'status': status})

def get_application_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Statistics/application.html', {'status': status})

def get_cvss_statistic(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status:
			status = False
		else:
			status = True
	except:
		status = False	
	if request.method == 'POST' and 'message' in request.POST:
		message = request.POST['message']
		response = ask_openai(message)

		return JsonResponse({'message': message, 'response': response})
	return render(request, 'firstapp/Statistics/cvss_statistic.html', {'status': status})