import os
import lasso

from pytest import fixture

from django.core.urlresolvers import reverse

from mellon.utils import create_metadata


@fixture
def idp_metadata():
    return open('tests/metadata.xml').read()


@fixture
def idp_private_key():
    return open('tests/idp-private-key.pem').read()


@fixture
def sp_private_key():
    return open('tests/sp-private-key.pem').read()


@fixture
def public_key():
    return open('tests/public-key.pem').read()


@fixture
def sp_settings(private_settings, idp_metadata, sp_private_key, public_key):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': idp_metadata,
    }]
    private_settings.MELLON_PUBLIC_KEYS = [public_key]
    private_settings.MELLON_PRIVATE_KEYS = [sp_private_key]
    private_settings.MELLON_NAME_ID_POLICY_FORMAT = lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
    private_settings.LOGIN_REDIRECT_URL = '/'
    return private_settings


@fixture
def sp_metadata(sp_settings, rf):
    request = rf.get('/')
    return create_metadata(request)


class MockIdp(object):
    def __init__(self, idp_metadata, private_key, sp_metadata):
        self.server = server = lasso.Server.newFromBuffers(idp_metadata, private_key)
        server.addProviderFromBuffer(lasso.PROVIDER_ROLE_SP, sp_metadata)

    def process_authn_request_redirect(self, url, auth_result=True, consent=True):
        login = lasso.Login(self.server)
        login.processAuthnRequestMsg(url.split('?', 1)[1])
        try:
            login.validateRequestMsg(auth_result, consent)
        except lasso.LoginRequestDeniedError:
            login.buildAuthnResponseMsg()
        else:
            login.buildAssertion(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD,
                                 "FIXME",
                                 "FIXME",
                                 "FIXME",
                                 "FIXME")
            login.buildAuthnResponseMsg()
        return login.msgUrl, login.msgBody


@fixture
def idp(sp_settings, idp_metadata, idp_private_key, sp_metadata):
    return MockIdp(idp_metadata, idp_private_key, sp_metadata)


def test_sso_slo(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'])
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), {'SAMLResponse': body})
    assert 'created new user' in caplog.text()
    assert 'logged in using SAML' in caplog.text()
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)


def test_sso(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'])
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), {'SAMLResponse': body})
    assert 'created new user' in caplog.text()
    assert 'logged in using SAML' in caplog.text()
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)


def test_sso_request_denied(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'], auth_result=False)
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), {'SAMLResponse': body})
    assert "status is not success codes: [u'urn:oasis:names:tc:SAML:2.0:status:Responder',\
 u'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text()
