from django.contrib import admin
from django.urls import path
from .views import get_home, get_list_CVE

app_name = 'app'

urlpatterns = [
    path('', get_home,name='home'),
    path('list-cve/', get_list_CVE,name='list_cves')
]
