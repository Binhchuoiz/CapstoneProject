from django.contrib import admin
from django.urls import path
from .views import get_home, get_list_CVE,get_detail_cves,get_tele_notifi,get_gmail_notifi,get_list_Products,get_about,get_list_definations,get_cve_definations,get_cvss_definations,get_cvss_compare,get_base_definations,get_temporal_definations,get_environmental_definations,get_difference_definations,get_type_definations,get_list_statistic,get_cve_statistic,get_risk_statistic,get_application_statistic,get_cvss_statistic,get_list_problems,get_cwe_definations,get_guidelines,list_cves_by_problem,get_search_list_CVE

app_name = 'app'

urlpatterns = [
    path('', get_home,name='home'),
    path('list-cve/<int:page>/', get_list_CVE,name='list_cves'),
    path('list-products/<int:page>/', get_list_Products,name='list_products'),
    path('detail-cve/<int:pk>', get_detail_cves, name='detail_cves'),
    path('telegram-notification/', get_tele_notifi, name='tele_noti'),
	path('gmail-notification/', get_gmail_notifi, name='gmail_noti'),
    path('about/', get_about, name='about'),
    path('list-defination/', get_list_definations, name='list_defination'),
    path('cve/', get_cve_definations, name='cve'),
    path('cwe/', get_cwe_definations, name='cwe'),
    path('cvss/', get_cvss_definations, name='cvss'),
    path('compare/', get_cvss_compare, name='cvss_comparation'),
    path('base/', get_base_definations, name='base'),
    path('temporal/', get_temporal_definations, name='temporal'),
    path('environmental/', get_environmental_definations, name='environmental'),
    path('difference/', get_difference_definations, name='difference'),
    path('type/', get_type_definations, name='type'),
    path('list-statistic/', get_list_statistic, name='list_statistic'),
    path('cve-statistic/', get_cve_statistic, name='cve_statistic'),
    path('risk/', get_risk_statistic, name='risk'),
    path('application/', get_application_statistic, name='application'),
    path('cvss-statistic/', get_cvss_statistic, name='cvss_statistic'),
    path('list-problems/<int:page>/', get_list_problems, name='list_problems'),
    path('guidelines/', get_guidelines, name='guidelines'),
    path('list-cves-by-problem/', list_cves_by_problem, name='list_cves_by_problem'),
    # path('search/<int:page>/', get_search_list_CVE,name='search'),
]