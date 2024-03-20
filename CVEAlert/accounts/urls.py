from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
	path('login/', views.get_login, name='login'),
    path('sign-up/', views.get_sign_up, name='sign_up'),
]