from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
	path('login/', views.get_login, name='login'),
    path('sign-up/', views.get_sign_up, name='sign_up'),
    path('log-out/', views.get_logout, name='log_out'),
    path('profile/', views.profile_detail_view, name='profile'),
]