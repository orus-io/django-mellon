import django

from django.conf.urls import url, include
from django.http import HttpResponse


def homepage(request):
    return HttpResponse('ok')

urlpatterns = [
    url('^', include('mellon.urls')),
    url('^$', homepage, name='homepage'),
]
