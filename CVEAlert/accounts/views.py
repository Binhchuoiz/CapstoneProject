from django.shortcuts import render


# Create your views here.

def get_login(request):
    return render(request, 'accounts/login.html')


def get_sign_up(request):
    return render(request, 'accounts/sign_up.html')

