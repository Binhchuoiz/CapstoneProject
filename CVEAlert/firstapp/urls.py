from django.contrib import admin
from django.urls import path
from .views import get_home, get_list_CVE,get_detail_cves,get_tele_notifi,get_gmail_notifi,create_cve_view,create_affect_view

app_name = 'app'

urlpatterns = [
    path('', get_home,name='home'),
    path('list-cve/<int:page>/', get_list_CVE,name='list_cves'),
    path('detail-cve/<int:pk>', get_detail_cves, name='detail_cves'),
    path('create-cve/', create_cve_view, name = 'create_cve'),
    path('create-affected/', create_affect_view, name = 'create_affected'),
    path('telegram-notification/', get_tele_notifi, name='tele_noti'),
	path('gmail-notification/', get_gmail_notifi, name='gmail_noti')
]