from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE , Affected , References , Metric , CvssV31 , Products , Vendors , Descriptions , Solutions 
# Create your views here.
def get_home(request):
    listCVE= CVE.objects.all().order_by('-date_publish')[:3]
    affected = Affected.objects.filter(con__in=listCVE)
    products = [a.product for a in affected]
    vendors = [a.vendor for a in affected]
    context={
        # 'list_cve':[1,2,3,4],
        'listCVE': listCVE,
        'products' : products,
        'vendors' : vendors,
        'affected': affected,
    }
    return render(request,'home.html', context=context)

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
    affected = Affected.objects.filter(con__in=listCVE)
    products = [a.products for a in affected]
    vendors = [a.vendors for a in affected]

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
    vendors = [a.vendor for a in affected]
    cvssv31 = CvssV31.objects.get(pk=pk) 
    metric = Metric.objects.filter(cvssv31_id=cvssv31.id)
    solutions = Solutions.objects.get(pk=pk)
    descriptions = Descriptions.objects.get(pk=pk)
    refrences = References.objects.filter(con_id=CVE.id)

    context = {
         'detail_cve': detail_cve,
         'products' : products,
         'vendors' : vendors,
         'affected': affected,
         'metric' : metric,
         'solutions' : solutions,
         'descriptions' : descriptions,
         'refrences' : refrences

    }

    return render(request, 'firstapp/detail_cve.html' , context=context)

def get_tele_notifi(request):

	return render(request, 'telegram_notifi.html')


def get_gmail_notifi(request):
	
	return render(request, 'gmail_notifi.html')