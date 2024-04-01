from django.urls import path
from .views import chathome,room,checkview,send,getMessages
app_name = 'app1'
urlpatterns = [
    path('chathome/', chathome, name='chathome'),
    path('<str:room>/', room, name='room'),
    path('checkview', checkview, name='checkview'),
    path('send', send, name='send'),
    path('getMessages/<str:room>/', getMessages, name='getMessages'),
]