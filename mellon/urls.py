from django.conf.urls import patterns, url
import django

from . import views


urlpatterns = [
    url('login/$', views.login,
        name='mellon_login'),
    url('logout/$', views.logout,
        name='mellon_logout'),
    url('metadata/$', views.metadata,
        name='mellon_metadata')
]
if django.VERSION < (1, 9):
    urlpatterns = patterns('', *urlpatterns)
