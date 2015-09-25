from django.utils.http import urlencode
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse

from . import app_settings, utils

PASSIVE_TRIED_COOKIE = 'MELLON_PASSIVE_TRIED'


class PassiveAuthenticationMiddleware(object):
    def process_response(self, request, response):
        # When unlogged remove the PASSIVE_TRIED cookie
        if app_settings.OPENED_SESSION_COOKIE_NAME \
           and PASSIVE_TRIED_COOKIE in request.COOKIES \
           and app_settings.OPENED_SESSION_COOKIE_NAME not in request.COOKIES:
            response.delete_cookie(PASSIVE_TRIED_COOKIE)
        return response

    def process_request(self, request):
        if not any(utils.get_idps()):
            return
        if not app_settings.OPENED_SESSION_COOKIE_NAME:
            return
        if hasattr(request, 'user') and request.user.is_authenticated():
            return
        if PASSIVE_TRIED_COOKIE in request.COOKIES:
            return
        if app_settings.OPENED_SESSION_COOKIE_NAME in request.COOKIES:
            # get the common domain or guess
            common_domain = app_settings.OPENED_SESSION_COOKIE_DOMAIN
            if not common_domain:
                common_domain = request.META['SERVER_NAME'].split('.', 1)[1]
                assert '.' in common_domain  # if domain is xxx.com explode !
            params = {
                'next': request.build_absolute_uri(),
                'passive': '',
            }
            url = reverse('mellon_login') + '?%s' % urlencode(params)
            response = HttpResponseRedirect(url)
            # prevent loops
            response.set_cookie(PASSIVE_TRIED_COOKIE, value='1', max_age=None)
            return response
