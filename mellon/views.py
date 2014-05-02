import logging

from django.views.generic import View
from django.http import HttpResponseBadRequest, HttpResponseRedirect, HttpResponse
from django.contrib import auth
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, resolve_url
from django.utils.http import same_origin

import lasso

from . import app_settings, utils

log = logging.getLogger(__name__)

class LoginView(View):
    def get_idp(self, request):
        entity_id = request.REQUEST.get('entity_id')
        if not entity_id:
            return app_settings.IDENTITY_PROVIDERS[0]
        else:
            for idp in app_settings.IDENTITY_PROVIDERS:
                if idp.entity_id == entity_id:
                    return idp

    def post(self, request, *args, **kwargs):
        '''Assertion consumer'''
        if 'SAMLResponse' not in request.POST:
            return self.get(request, *args, **kwargs)
        login = utils.create_login(request)
        try:
            login.processAuthnResponseMsg(request.POST['SAMLResponse'])
            login.acceptSso()
        except lasso.ProfileStatusNotSuccessError, e:
            status_codes = []
            status = login.response.status
            a = status
            while a.statusCode:
                status_codes.append(a.statusCode.value)
                a = a.statusCode
            log.warning('SAML authentication failed, codes: %r',
                    status_codes)
            if status.statusMessage:
                log.warning('SAML authentication failed, message: %r',
                        status.statusMessage)
            next_url = login.msgRelayState or \
                    resolve_url(settings.LOGIN_REDIRECT_URL)
            return render(request, 'mellon/authentication_failed.html', {
                      'status_message': status.statusMessage,
                      'status_codes': status_codes,
                      'issuer': login.remoteProviderId,
                      'next_url': next_url,
                    })
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing the authentication '
                    'response: %r' % e)
        name_id = login.nameIdentifier
        attributes = {}
        attribute_statements = login.assertion.attributeStatement
        for ats in attribute_statements:
            for at in ats.attribute:
                values = attributes.setdefault(at.name, [])
                for value in at.attributeValue:
                    content = [any.exportToXml() for any in value.any]
                    content = ''.join(content)
                    values.append(content.decode('utf8'))
        attributes.update({
            'issuer': name_id.nameQualifier or login.remoteProviderId,
            'name_id_content': name_id.content,
            'name_id_format': name_id.format,
            'name_id_name_qualifier': name_id.nameQualifier,
            'name_id_sp_name_qualifier': name_id.spNameQualifier,
        })
        authn_statement = login.assertion.authnStatement[0]
        if authn_statement.authnInstant:
            attributes['authn_instant'] = utils.iso8601_to_datetime(authn_statement.authnInstant)
        if authn_statement.sessionNotOnOrAfter:
            attributes['session_not_on_or_after'] = utils.iso8601_to_datetime(authn_statement.sessionNotOnOrAfter)
        if authn_statement.sessionIndex:
            attributes['session_index'] = authn_statement.sessionIndex
        attributes['authn_context_class_ref'] = ()
        if authn_statement.authnContext:
            authn_context = authn_statement.authnContext
            if authn_context.authnContextClassRef:
                attributes['authn_context_class_ref'] = \
                    authn_context.authnContextClassRef
        log.debug('trying to authenticate with attributes %r', attributes)
        user = auth.authenticate(saml_attributes=attributes)
        if user is not None:
            if user.is_active:
                auth.login(request, user)
                request.session['mellon_session'] = utils.flatten_datetime(attributes)
                if 'session_not_on_or_after' in attributes:
                    request.session.set_expiry(attributes['session_not_on_or_after'])
            else:
                return render(request, 'mellon/inactive_user.html', {
                    'user': user,
                    'saml_attributes': attributes})
        else:
            return render(request, 'mellon/user_not_found.html', {
                'saml_attributes': attributes })
        next_url = login.msgRelayState or resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(next_url)

    def get(self, request, *args, **kwargs):
        '''Initialize login request'''
        next_url = request.GET.get('next')
        idp = self.get_idp(request)
        if idp is None:
            return HttpResponseBadRequest('unkown entity_id')
        login = utils.create_login(request)
        log.debug('authenticating to %r', idp['ENTITY_ID'])
        try:
            login.initAuthnRequest(idp['ENTITY_ID'],
                    lasso.HTTP_METHOD_REDIRECT)
            authn_request = login.request
            # configure NameID policy
            policy = authn_request.nameIdPolicy
            policy_format = idp.get('NAME_ID_POLICY_FORMAT') or app_settings.NAME_ID_POLICY_FORMAT
            policy.format = policy_format or None
            force_authn = idp.get('FORCE_AUTHN') or app_settings.FORCE_AUTHN
            if force_authn:
                policy.forceAuthn = True
            if request.GET.get('passive') == '1':
                policy.isPassive = True
            # configure requested AuthnClassRef
            authn_classref = idp.get('AUTHN_CLASSREF') or app_settings.AUTHN_CLASSREF
            if authn_classref:
                req_authncontext = lasso.RequestedAuthnContext()
                authn_request.requestedAuthnContext = req_authncontext
                req_authncontext.authnContextClassRef = authn_classref
            if next_url:
                login.msgRelayState = next_url
            login.buildAuthnRequestMsg()
        except lasso.Error, e:
            return HttpResponseBadRequest('error initializing the '
                    'authentication request: %r' % e)
        log.debug('sending authn request %r', authn_request.dump())
        log.debug('to url %r', login.msgUrl)
        return HttpResponseRedirect(login.msgUrl)

login = csrf_exempt(LoginView.as_view())

class LogoutView(View):
    def get(self, request):
        if 'SAMLRequest' in request.GET:
            return self.idp_logout(request)
        elif 'SAMLResponse' in request.GET:
            return self.sp_logout_response(request)
        else:
            return self.sp_logout_request(request)

    def idp_logout(self, request):
        '''Handle logout request emitted by the IdP'''
        logout = utils.create_logout(request)
        try:
            logout.processRequestMsg(request.META['QUERY_STRING'])
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing logout request: %r' % e)
        try:
            logout.validateRequest()
        except lasso.Error, e:
            log.warning('error validating logout request: %r' % e)
        issuer = request.session.get('mellon_session', {}).get('issuer')
        if issuer == logout.remoteProviderId:
            auth.logout(request)
        try:
            logout.buildResponseMsg()
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing logout request: %r' % e)
        return HttpResponseRedirect(logout.msgUrl)

    def sp_logout_request(self, request):
        '''Launch a logout request to the identity provider'''
        next_url = resolve_url(settings.LOGIN_REDIRECT_URL)
        next_url = request.GET.get('next') or next_url
        referer = request.META.get('HTTP_REFERER')
        if not referer or same_origin(referer, request.build_absolute_uri()):
            if request.user.is_authenticated():
                try:
                    issuer = request.session.get('mellon_session', {}).get('issuer')
                    if issuer:
                        logout = utils.create_logout(request)
                        try:
                            logout.initRequest(issuer, lasso.HTTP_METHOD_REDIRECT)
                            logout.msgRelayState = next_url
                            logout.buildRequestMsg()
                        except lasso.Error, e:
                            log.error('unable to initiate a logout request %r', e)
                        else:
                            log.debug('sending LogoutRequest %r', logout.request.dump())
                            log.debug('to URL %r', logout.msgUrl)
                            return HttpResponseRedirect(logout.msgUrl)
                finally:
                   auth.logout(request)
        else:
            log.warning('logout refused referer %r is not of the '
                    'same origin', referer)
        return HttpResponseRedirect(next_url)

    def sp_logout_response(self, request):
        '''Launch a logout request to the identity provider'''
        next_url = resolve_url(settings.LOGIN_REDIRECT_URL)
        if 'SAMLResponse' not in request.GET:
            return HttpResponseRedirect(next_url)
        logout = utils.create_logout(request)
        try:
            logout.processResponseMsg(request.META['QUERY_STRING'])
        except lasso.Error, e:
            log.error('unable to process a logout response %r', e)
        if logout.msgRelayState and same_origin(logout.msgRelayState, request.build_absolute_uri()):
            return redirect(logout.msgRelayState)
        return redirect(next_url)


logout = LogoutView.as_view()


def metadata(request):
    metadata = utils.create_metadata(request)
    return HttpResponse(metadata, content_type='text/xml')
