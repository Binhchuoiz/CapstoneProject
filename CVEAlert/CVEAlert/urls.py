from django.contrib import admin
from django.urls import path, include
from firstapp import views as firstapp 
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('firstapp.urls'))
]
