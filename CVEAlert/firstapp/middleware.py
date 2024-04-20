# middleware.py

from django.http import HttpResponseNotFound

class ErrorTo404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # If the response status code indicates an error, replace it with 404
        if response.status_code >= 400:
            return HttpResponseNotFound('<h1>Page not found</h1>')
        return response
