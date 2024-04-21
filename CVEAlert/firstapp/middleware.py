# middleware.py

from django.http import HttpResponseNotFound
from django.template.loader import render_to_string

# class ErrorTo404Middleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         response = self.get_response(request)
#         # If the response status code indicates an error, replace it with 404
#         if response.status_code >= 400:
#             return HttpResponseNotFound('<h1>Page not found</h1>')
        
#         return response

class ErrorTo404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if response.status_code >= 400:
            # Render the 404 template without a response object
            context = {}  # Add any additional context data if needed
            template_content = render_to_string('404.html', context)
            return HttpResponseNotFound(template_content, status=404)

        return response
