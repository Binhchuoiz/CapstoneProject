from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE 
# Create your views here.
def get_home(request):
    listCVE= CVE.objects.all().order_by('-date_publish')[:3]
    context={
        # 'list_cve':[1,2,3,4],
        'listCVE':listCVE
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

    context={
        "page" :{
            'current' : page_obj.number,
            'has_next' : page_obj.has_next,
            'has_previous' : page_obj.has_previous,
        },
        'paginator': paginator,
        'listCVE':data,
    }

    # print(listCVE)
    return render(request, 'firstapp/list_cves.html', context=context)   

def get_detail_cves(request):
    return render(request, 'firstapp/detail_cve.html')

def get_tele_notifi(request):

	return render(request, 'telegram_notifi.html')


def get_gmail_notifi(request):
	
	return render(request, 'gmail_notifi.html')