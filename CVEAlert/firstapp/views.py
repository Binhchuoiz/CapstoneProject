from django.shortcuts import render, HttpResponseRedirect, redirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE , Affected , References , Metric , CvssV31 , Products , Vendors , Descriptions , Solutions , Products_Versions , Follow_Product , Follow_CVE
from accounts.models import NotiUser
from .forms import CVEform,AffectedForm
from django.db.models import F, DateTimeField , ExpressionWrapper , Value , CharField , Case , When , Q , Count
from django.db.models.functions import Cast 
from django.http import JsonResponse
from CVEAlert.chatbot import ask_openai
import json
# Create your views here.
def get_home(request):
    listCVE = CVE.objects.all().order_by('-date_publish')[:3] 
    cve_ids = [cve.id for cve in listCVE] 
    affected = Affected.objects.filter(con_id__in=cve_ids) 
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]
    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
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
    return render(request, 'index.html', context=context)


from django.db.models import F, Value, CharField, Case, When

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
        if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
            status = False
        else:
            status = True
    except:
            status = False
            
    if request.method == 'POST':
        selected_years = request.POST.getlist('filter_year')
        if selected_years:
            selected_year = selected_years[0]  
            listCVE = CVE.objects.filter(year__in=selected_years)
            page = 1
        if 'search_focus' in request.POST:
            search_focus = request.POST['search_focus']
            listCVE = listCVE.filter(cve_id__contains=search_focus)
            page = 1
            
        # Sorting based on CVSS versions (v31, v30, v20) or date fields
        sort_order = request.POST.get('sort_order')
        sort_by = request.POST.get('sort_by')
        cvss_score_field = Case(
            When(metric_cve__cvssv31__isnull=False, then=F('metric_cve__cvssv31__base_score')),
            When(metric_cve__cvssv30__isnull=False, then=F('metric_cve__cvssv30__base_score')),
            When(metric_cve__cvssv20__isnull=False, then=F('metric_cve__cvssv20__base_score')),
            default=Value(''), output_field=CharField(),
        )
        if sort_by == 'cvss':
            if sort_order == 'asc':
                listCVE = listCVE.annotate(cvss_score=cvss_score_field).order_by('cvss_score')
            else:
                listCVE = listCVE.annotate(cvss_score=cvss_score_field).order_by('-cvss_score')
        elif sort_by == 'date_publish':
            if sort_order == 'asc':
                listCVE = listCVE.order_by('date_publish')
            else:
                listCVE = listCVE.order_by('-date_publish')
        elif sort_by == 'date_update':
            if sort_order == 'asc':
                listCVE = listCVE.order_by('date_update')
            else:
                listCVE = listCVE.order_by('-date_update')
        
        # Filter CVEs based on minimum and maximum CVSS scores
        cvss_min = request.POST.get('cvss_min')
        cvss_max = request.POST.get('cvss_max')
        if cvss_min and cvss_max:
            cvss_min = float(cvss_min)
            cvss_max = float(cvss_max)
            listCVE = listCVE.filter(
                (Q(metric_cve__cvssv31__base_score__gte=cvss_min) & Q(metric_cve__cvssv31__base_score__lte=cvss_max)) |
                (Q(metric_cve__cvssv30__base_score__gte=cvss_min) & Q(metric_cve__cvssv30__base_score__lte=cvss_max)) |
                (Q(metric_cve__cvssv20__base_score__gte=cvss_min) & Q(metric_cve__cvssv20__base_score__lte=cvss_max))
            )
        
    else:
        search_focus = request.GET.get('search_focus', None)
        selected_year = request.GET.get('filter_year', None)
        if selected_year:
            listCVE = listCVE.filter(year=selected_year)
        if search_focus:
            listCVE = listCVE.filter(cve_id__contains=search_focus)
    
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
    metric = Metric.objects.filter(con_id__in=cve_ids)
    cvss_v31 = {}
    for m in metric:
        if m.con_id in cvss_v31:
            cvss_v31[m.con_id].append(m.cvssv31)
        else:
            cvss_v31[m.con_id] = [m.cvssv31]
    page_obj.metric = metric
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

    return render(request, 'firstapp/list_cves.html', context=context)







def get_list_Products(request, page):
    letter = None
    search_focus = None
    list_products = Products.objects.all().order_by('name')
    
    try:
        check_user_notifi = NotiUser.objects.get(user=request.user)
        if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
            status = False
        else:
            status = True
    except:
        status = False
    
    if request.method == 'POST':
        letter = request.POST.get('letter')
        if letter:
            list_products = Products.objects.filter(name__istartswith=letter).order_by('name')
            page = 1
        if 'message' in request.POST:
            message = request.POST['message']
            response = ask_openai(message)
            return JsonResponse({'message': message, 'response': response})
        elif 'search_focus' in request.POST:
            search_focus = request.POST['search_focus']
            list_products = list_products.filter(name__icontains=search_focus)
            page = 1
        elif 'selected_products_localstorage' in request.POST:
            user = request.user
            selected_products_localstorage = json.loads(request.POST.get('selected_products_localstorage'))
            products = Products.objects.filter(name__in=selected_products_localstorage)
            for p in products:
                Follow_Product.objects.get_or_create(user=user, product=p)
            page = 1
    else:
        letter = request.GET.get('letter', None)
        search_focus = request.GET.get('search_focus', None)
        if search_focus:
            list_products = list_products.filter(name__icontains=search_focus)
        if letter:
            list_products = Products.objects.filter(name__istartswith=letter).order_by('name')
    
    # Count the number of CVEs related to each product
    # list_products = list_products.annotate(num_cves=Count('id__con', distinct=True))
    
    per_page = request.GET.get("per_page", 10)
    paginator = Paginator(list_products, per_page)
    page_obj = paginator.get_page(page)
    
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
        'letter': letter,
        'search_focus': search_focus,
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

# def create_cve_view(request):
# 	try:
# 		check_user_notifi = NotiUser.objects.get(user=request.user)
# 		if not check_user_notifi.status:
# 			status = False
# 		else:
# 			status = True
# 	except:
# 		status = False
# 	form = CVEform()
# 	# bot chat
# 	if request.method == 'POST' and 'message' in request.POST:
# 		message = request.POST['message']
# 		response = ask_openai(message)

# 		return JsonResponse({'message': message, 'response': response})
# 	elif request.method == 'POST':
# 		form = AffectedForm(request.POST or None, request.FILES)
# 		if form.is_valid():
# 			data = form.save(commit=True)
# 			return HttpResponseRedirect(reverse('app:home'))

# 	context = {
# 		'form': form,
# 		'status': status
# 	}
# 	return render(request, 'firstapp/create_cves.html', context=context)


# def create_affect_view(request):
# 	try:
# 		check_user_notifi = NotiUser.objects.get(user=request.user)
# 		if not check_user_notifi.status:
# 			status = False
# 		else:
# 			status = True
# 	except:
# 		status = False
# 	form = AffectedForm()
# 	# bot chat
# 	if request.method == 'POST' and 'message' in request.POST:
# 		message = request.POST['message']
# 		response = ask_openai(message)

# 		return JsonResponse({'message': message, 'response': response})
# 	elif request.method == 'POST':
# 		form = AffectedForm(request.POST)
# 		if form.is_valid():
# 			data = form.save(commit=True)
# 			return HttpResponseRedirect(reverse('app:home'))

# 	context = {
# 		'form': form,
# 		'status': status
# 	}
# 	return render(request, 'firstapp/create_affected.html', context=context)


def get_tele_notifi(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'telegram_notifi.html', {'status': status})


def get_gmail_notifi(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
		if not check_user_notifi.status or check_user_notifi.email_address =='' and check_user_notifi.token_bot =='':
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
	return render(request, 'firstapp/about.html', {'status': status})


def get_list_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/list_definations.html', {'status': status})


def get_cve_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/cve.html', {'status': status})

def get_cvss_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/cvss.html', {'status': status})

def get_cvss_compare(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/comparecvss.html', {'status': status})

def get_base_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/base.html', {'status': status})


def get_temporal_definations(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/temporal.html', {'status': status})

def get_environmental_definations(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/environmental.html', {'status': status})

def get_difference_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/difference.html', {'status': status})

def get_type_definations(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Definations/product_and_vendor.html', {'status': status})

def get_list_statistic(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/list_statistics.html', {'status': status})

def get_cve_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Statistics/cve_statistic.html', {'status': status})

def get_risk_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Statistics/risk.html', {'status': status})

def get_application_statistic(request):	
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Statistics/application.html', {'status': status})

def get_cvss_statistic(request):
	try:
		check_user_notifi = NotiUser.objects.get(user=request.user)
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
	return render(request, 'firstapp/Statistics/cvss_statistic.html', {'status': status})