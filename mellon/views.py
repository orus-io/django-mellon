import logging

from django.views.generic import View
from django.http import HttpResponseBadRequest, HttpResponseRedirect, HttpResponse
from django.contrib import auth
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

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
        next_url = login.msgRelayState or settings.LOGIN_REDIRECT_URL
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
    pass

logout = LogoutView.as_view()

def metadata(request):
    metadata = utils.create_metadata(request)
    return HttpResponse(metadata, content_type='text/xml')
