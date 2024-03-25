from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
	path('login/', views.get_login, name='login'),
    path('sign-up/', views.get_sign_up, name='sign_up'),
    path('log-out/', views.get_logout, name='log_out'),
    path('profile/', views.profile_detail_view, name='profile'),
    path('change-password', views.change_password_view, name='change_password'),
    path('list-affect', views.list_affect_view, name='list_affect'),
	path('notification/', views.notification_user_view, name='notification'),
]