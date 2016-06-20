import django

from django.conf.urls import patterns, url, include
from django.http import HttpResponse


def homepage(request):
    return HttpResponse('ok')

urlpatterns = [
    url('^', include('mellon.urls')),
    url('^$', homepage, name='homepage'),
]

if django.VERSION < (1, 9):
    urlpatterns = patterns('', *urlpatterns)
