from django.shortcuts import render, HttpResponseRedirect
from django.urls import reverse
from django.core.paginator import Paginator, EmptyPage , PageNotAnInteger
from .models import CVE 
# Create your views here.
def get_home(request):
    return render(request,'home.html')

def get_list_CVE(request):
    listCVE= CVE.objects.all
    if request.method == 'POST':  
        # if 'search_focus' in request.POST:
        #    id_cve= request.POST['search_focus']
        #    listCVE = CVE.objects.filter(title_contains=id_cve)
        if 'newest' in request.POST:
            listCVE= CVE.objects.all().order_by('-date_publish')
        elif  'oldest' in request.POST:
         listCVE= CVE.objects.all().order_by('date_publish')

     
    context={
        #'list_cve':[1,2,3,4],
        'list_cve':listCVE
         }
    return render(request, 'firstapp/list_cves.html', context=context)   