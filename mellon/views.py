import logging
import requests
from requests.exceptions import RequestException

from django.views.generic import View
from django.http import HttpResponseBadRequest, HttpResponseRedirect, HttpResponse
from django.contrib import auth
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect, resolve_url
from django.utils.http import same_origin

import lasso

lasso.setFlag('thin-sessions')

from . import utils

class LogMixin(object):
    """Initialize a module logger in new objects"""
    def __init__(self, *args, **kwargs):
        self.log = logging.getLogger(__name__)
        super(LogMixin, self).__init__(*args, **kwargs)

class LoginView(LogMixin, View):
    def get_idp(self, request):
        entity_id = request.REQUEST.get('entity_id')
        if not entity_id:
            return next(utils.get_idps())
        else:
            return utils.get_idp(entity_id)

    def post(self, request, *args, **kwargs):
        '''Assertion consumer'''
        if 'SAMLResponse' not in request.POST:
            return self.get(request, *args, **kwargs)
        login = utils.create_login(request)
        idp_message = None
        status_codes = []
        try:
            login.processAuthnResponseMsg(request.POST['SAMLResponse'])
            login.acceptSso()
        except lasso.ProfileCannotVerifySignatureError:
            self.log.warning('SAML authentication failed: signature validation failed for %r',
                    login.remoteProviderId)
        except lasso.ParamError:
            self.log.exception('lasso param error')
        except (lasso.LoginStatusNotSuccessError,
                lasso.ProfileStatusNotSuccessError,
                lasso.ProfileRequestDeniedError):
            status = login.response.status
            a = status
            while a.statusCode:
                status_codes.append(a.statusCode.value)
                a = a.statusCode
            args = ['SAML authentication failed: status is not success codes: %r', status_codes]
            if status.statusMessage:
                idp_message = status.statusMessage.decode('utf-8')
                args[0] += ' message: %r'
                args.append(status.statusMessage)
            self.log.warning(*args)
        except lasso.Error, e:
            return HttpResponseBadRequest('error processing the authentication '
                    'response: %r' % e)
        else:
            if 'RelayState' in request.POST:
                login.msgRelayState = request.POST['RelayState']
            return self.sso_success(request, login)
        return self.sso_failure(request, login, idp_message, status_codes)

    def sso_failure(self, request, login, idp_message, status_codes):
        '''show error message to user after a login failure'''
        idp = utils.get_idp(login.remoteProviderId)
        error_url = utils.get_setting(idp, 'ERROR_URL')
        error_redirect_after_timeout = utils.get_setting(idp, 'ERROR_REDIRECT_AFTER_TIMEOUT')
        if error_url:
            error_url = resolve_url(error_url)
        next_url = error_url or login.msgRelayState or resolve_url(settings.LOGIN_REDIRECT_URL)
        return render(request, 'mellon/authentication_failed.html', {
                  'debug': settings.DEBUG,
                  'idp_message': idp_message,
                  'status_codes': status_codes,
                  'issuer': login.remoteProviderId,
                  'next_url': next_url,
                  'error_url': error_url,
                  'relaystate': login.msgRelayState,
                  'error_redirect_after_timeout': error_redirect_after_timeout,
                })

    def sso_success(self, request, login):
        attributes = {}
        attribute_statements = login.assertion.attributeStatement
        for ats in attribute_statements:
            for at in ats.attribute:
                values = attributes.setdefault(at.name, [])
                for value in at.attributeValue:
                    content = [any.exportToXml() for any in value.any]
                    content = ''.join(content)
                    values.append(content.decode('utf8'))
        attributes['issuer'] = login.remoteProviderId
        if login.nameIdentifier:
            name_id = login.nameIdentifier
            attributes.update({
                'name_id_content': name_id.content.decode('utf8'),
                'name_id_format': unicode(name_id.format or lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED),
            })
            if name_id.nameQualifier:
                attributes['name_id_name_qualifier'] = unicode(name_id.nameQualifier)
            if name_id.spNameQualifier:
                attributes['name_id_sp_name_qualifier'] = unicode(name_id.spNameQualifier)
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
        self.log.debug('trying to authenticate with attributes %r', attributes)
        return self.authenticate(request, login, attributes)

    def authenticate(self, request, login, attributes):
        user = auth.authenticate(saml_attributes=attributes)
        if user is not None:
            if user.is_active:
                auth.login(request, user)
                self.log.info('user %r (NameID is %r) logged in using SAML',
                        unicode(user), attributes['name_id_content'])
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
        request.session['lasso_session_dump'] = login.session.dump()
        next_url = login.msgRelayState or resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(next_url)

    def continue_sso_artifact_get(self, request):
        idp_message = None
        status_codes = []

        login = utils.create_login(request)
        try:
            login.initRequest(request.META['QUERY_STRING'], lasso.HTTP_METHOD_ARTIFACT_GET)
        except lasso.ServerProviderNotFoundError:
            self.log.warning('no entity id found for artifact %s',
                             request.GET['SAMLart'])
            return HttpResponseBadRequest(
                'no entity id found for this artifact %r' %
                request.GET['SAMLart'])
        idp = utils.get_idp(login.remoteProviderId)
        if not idp:
            self.log.warning('entity id %r is unknown', login.remoteProviderId)
            return HttpResponseBadRequest(
                'entity id %r is unknown' % login.remoteProviderId)
        verify_ssl_certificate = utils.get_setting(
            idp, 'VERIFY_SSL_CERTIFICATE')
        login.buildRequestMsg()
        try:
            result = requests.post(login.msgUrl, data=login.msgBody,
                headers={'content-type': 'text/xml'},
                verify=verify_ssl_certificate)
        except RequestException, e:
            self.log.warning('unable to reach %r: %s', login.msgUrl, e)
            return HttpResponseBadRequest('unable to reach %r: %s' % (login.msgUrl, e))
        if result.status_code != 200:
            self.log.warning('SAML authentication failed: '\
                             'IdP returned %s when given artifact', result.status_code)
            return self.sso_failure(request, login, idp_message, status_codes)

        try:
            login.processResponseMsg(result.content)
            login.acceptSso()
        except lasso.ProfileCannotVerifySignatureError:
            self.log.warning('SAML authentication failed: signature validation failed for %r',
                    login.remoteProviderId)
        except lasso.ParamError:
            self.log.exception('lasso param error')
        except (lasso.ProfileStatusNotSuccessError, lasso.ProfileRequestDeniedError):
            status = login.response.status
            a = status
            while a.statusCode:
                status_codes.append(a.statusCode.value)
                a = a.statusCode
            args = ['SAML authentication failed: status is not success codes: %r', status_codes]
            if status.statusMessage:
                idp_message = status.statusMessage.decode('utf-8')
                args[0] += ' message: %r'
                args.append(status.statusMessage)
            self.log.warning(*args)
        except lasso.Error, e:
            self.log.exception('unexpected lasso error')
            return HttpResponseBadRequest('error processing the authentication '
                    'response: %r' % e)
        else:
            if 'RelayState' in request.GET:
                login.msgRelayState = request.GET['RelayState']
            return self.sso_success(request, login)
        return self.sso_failure(request, login, idp_message, status_codes)

    def get(self, request, *args, **kwargs):
        '''Initialize login request'''
        if 'SAMLart' in request.GET:
            return self.continue_sso_artifact_get(request)
        next_url = request.GET.get('next')
        idp = self.get_idp(request)
        if idp is None:
            return HttpResponseBadRequest('unkown entity_id')
        login = utils.create_login(request)
        self.log.debug('authenticating to %r', idp['ENTITY_ID'])
        try:
            login.initAuthnRequest(idp['ENTITY_ID'],
                    lasso.HTTP_METHOD_REDIRECT)
            authn_request = login.request
            # configure NameID policy
            policy = authn_request.nameIdPolicy
            policy.allowCreate = utils.get_setting(idp, 'NAME_ID_POLICY_ALLOW_CREATE')
            policy.format = utils.get_setting(idp, 'NAME_ID_POLICY_FORMAT')
            force_authn = utils.get_setting(idp, 'FORCE_AUTHN')
            if force_authn:
                authn_request.forceAuthn = True
            if request.GET.get('passive') == '1':
                authn_request.isPassive = True
            # configure requested AuthnClassRef
            authn_classref = utils.get_setting(idp, 'AUTHN_CLASSREF')
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
        self.log.debug('sending authn request %r', authn_request.dump())
        self.log.debug('to url %r', login.msgUrl)
        return HttpResponseRedirect(login.msgUrl)

login = csrf_exempt(LoginView.as_view())

class LogoutView(LogMixin, View):
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
            self.log.warning('error validating logout request: %r' % e)
        issuer = request.session.get('mellon_session', {}).get('issuer')
        if issuer == logout.remoteProviderId:
            self.log.info('user %r logged out by SLO request',
                    unicode(request.user))
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
                            if request.session.has_key('lasso_session_dump'):
                                logout.setSessionFromDump(
                                        request.session['lasso_session_dump']
                                        )
                            else:
                                self.log.error('unable to find lasso session dump')
                            logout.initRequest(issuer, lasso.HTTP_METHOD_REDIRECT)
                            logout.msgRelayState = next_url
                            logout.buildRequestMsg()
                        except lasso.Error, e:
                            self.log.error('unable to initiate a logout request %r', e)
                        else:
                            self.log.debug('sending LogoutRequest %r', logout.request.dump())
                            self.log.debug('to URL %r', logout.msgUrl)
                            return HttpResponseRedirect(logout.msgUrl)
                finally:
                   auth.logout(request)
                   self.log.info('user %r logged out, SLO request sent',
                           unicode(request.user))
        else:
            self.log.warning('logout refused referer %r is not of the '
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
            self.log.error('unable to process a logout response %r', e)
        if logout.msgRelayState and same_origin(logout.msgRelayState, request.build_absolute_uri()):
            return redirect(logout.msgRelayState)
        return redirect(next_url)


logout = LogoutView.as_view()


def metadata(request):
    metadata = utils.create_metadata(request)
    return HttpResponse(metadata, content_type='text/xml')
