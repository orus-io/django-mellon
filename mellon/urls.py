from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('',
                       url('login/$', views.login,
                           name='mellon_login'),
                       url('logout/$', views.logout,
                           name='mellon_logout'),
                       url('metadata/$', views.metadata,
                           name='mellon_metadata'))
