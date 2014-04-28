from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('',
                       url('^accounts/mellon/login/$', views.login,
                           name='mellon_login'),
                       url('^accounts/mellon/logout/$', views.logout,
                           name='mellon_logout'),
                       url('^accounts/mellon/metadata/$', views.metadata,
                           name='mellon_metadata'),
)
