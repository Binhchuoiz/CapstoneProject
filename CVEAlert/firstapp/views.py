from django.shortcuts import render
from .models import CVE 
# Create your views here.
def get_home(request):
    return render(request,'home.html')

def get_list_CVE(request):
    listCVE= CVE.objects.all
    return render(request, 'firstapp/list_cves.html')   