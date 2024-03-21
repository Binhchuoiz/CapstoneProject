from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE , Affected , References , Metric , CvssV31 , Products , Vendors , Descriptions , Solutions , Products_Versions
# Create your views here.
def get_home(request):
    listCVE = CVE.objects.all().order_by('-date_publish')[:3]
    cve_ids = [cve.id for cve in listCVE] 
    affected = Affected.objects.filter(con_id__in=cve_ids) 
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]
    context = {
        'listCVE': listCVE,
        'products': products,
        'vendors': vendors,
        'affected': affected,
    }
    return render(request, 'home.html', context=context)

def get_list_CVE(request, page):
    listCVE= CVE.objects.all()
    if request.method == 'POST':  
        # if 'search_focus' in request.POST:
        # id_cve= request.POST['search_focus']
        # listCVE = CVE.objects.filter(title_contains=id_cve)
        if 'newest' in request.POST:
            listCVE= CVE.objects.all().order_by('-date_publish')
        elif  'oldest' in request.POST:
            listCVE= CVE.objects.all().order_by('date_publish')
    
    per_page = request.GET.get("per_page", 10)
    paginator = Paginator(listCVE, per_page)
    page_obj = paginator.get_page(page)
    data = page_obj.object_list
    cve_ids = [cve.id for cve in listCVE] 
    affected = Affected.objects.filter(con_id__in=cve_ids) 
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]

    context={
        "page" :{
            'current' : page_obj.number,
            'has_next' : page_obj.has_next,
            'has_previous' : page_obj.has_previous,
        },
        'paginator': paginator,
        'listCVE':data,
        'products' : products,
        'vendors' : vendors,
        'affected': affected

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