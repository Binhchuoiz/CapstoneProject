from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE , Affected , References , Metric , CvssV31 , Products , Vendors , Descriptions , Solutions , Products_Versions 
from django.db.models import F, DateTimeField , ExpressionWrapper
from django.db.models.functions import Cast
# Create your views here.
def get_home(request):
    listCVE = CVE.objects.all().order_by('-date_publish')[:3]
    cve_ids = [cve.id for cve in listCVE] 
    affected = Affected.objects.filter(con_id__in=cve_ids) 
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]
    if request.method == 'POST': 
            id_cve= request.POST['id_cve']
            listCVE = CVE.objects.filter(cve_id__contains=id_cve)[:12]
    context = {
        'listCVE': listCVE,
        'products': products,
        'vendors': vendors,
        'affected': affected,
    }
    return render(request, 'home.html', context=context)

def get_list_CVE(request, page):
    listCVE= CVE.objects.all().order_by('date_publish')
    year = CVE.objects.values_list('year',flat=True)
    unique_Year = set(year)
    unique_year_List = list(unique_Year)
    unique_year_List.sort()
    if request.method == 'POST':
        selected_years = request.POST.getlist('filter_year')
        if selected_years:
            listCVE = CVE.objects.filter(year__in=selected_years)
    if request.method == 'POST':  
        if 'search_focus' in request.POST:
            id_cve= request.POST['search_focus']
            listCVE = CVE.objects.filter(cve_id__contains=id_cve)
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
             products = Products.objects.filter(name__in=product_Name)
    if request.method == 'POST' and 'search_focus' in request.POST and 'vendors' in request.POST:
             vendors_Name = request.POST['search_focus']
             vendors = Vendors.objects.filter(name__in=vendors_Name)   
    # print(unique_year_List)
    context={
        "page": {
			'prev': page_obj.number - 1 if page_obj.number - 1 > 0 else 1,
			'current': page_obj.number,
			'next': page_obj.number + 1 if page_obj.number + 1 < paginator.num_pages else paginator.num_pages,
		},
        'paginator': paginator,
        'page_obj' : page_obj,
        'products' : products,
        'vendors' : vendors,
        'affected' : affected,
        'unique_year' : unique_year_List
        

    }

    # print(listCVE)
    return render(request, 'firstapp/list_cves.html', context=context)   

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
         'cvssv31' : cvssv31

    }

    return render(request, 'firstapp/detail_cve.html' , context=context)

def get_tele_notifi(request):

	return render(request, 'telegram_notifi.html')


def get_gmail_notifi(request):
	
	return render(request, 'gmail_notifi.html')