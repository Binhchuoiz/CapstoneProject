from django.contrib import admin
from django.urls import path
from firstapp import views as firstapp 

app_name = 'app'

urlpatterns = [
    path('', firstapp.get_list_CVE,name='list_cves')
]
