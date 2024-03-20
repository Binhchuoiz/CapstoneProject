from django.contrib import admin
from django.urls import path
from .views import get_home, get_list_CVE,get_detail_cves

app_name = 'app'

urlpatterns = [
    path('', get_home,name='home'),
    path('list-cve/', get_list_CVE,name='list_cves'),
    path('detail-cve/', get_detail_cves, name='detail_cves')
]
