import lasso

from pytest import fixture

from django.core.urlresolvers import reverse
from django.utils import six

from mellon.utils import create_metadata

from httmock import all_requests, HTTMock, response as mock_response

from utils import reset_caplog


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
            pass
        else:
            login.buildAssertion(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD,
                                 "FIXME",
                                 "FIXME",
                                 "FIXME",
                                 "FIXME")
        if login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART:
            login.buildArtifactMsg(lasso.HTTP_METHOD_ARTIFACT_GET)
            self.artifact = login.artifact
            self.artifact_message = login.artifactMessage
        elif login.protocolProfile == lasso.LOGIN_PROTOCOL_PROFILE_BRWS_POST:
            login.buildAuthnResponseMsg()
        else:
            raise NotImplementedError
        return login.msgUrl, login.msgBody

    def resolve_artifact(self, soap_message):
        login = lasso.Login(self.server)
        login.processRequestMsg(soap_message)
        if hasattr(self, 'artifact') and self.artifact == login.artifact:
            # artifact is known, go on !
            login.artifactMessage = self.artifact_message
            # forget the artifact
            del self.artifact
            del self.artifact_message
        login.buildResponseMsg()
        return login.msgBody

    def mock_artifact_resolver(self):
        @all_requests
        def f(url, request):
            content = self.resolve_artifact(request.body)
            return mock_response(200, content=content,
                                 headers={'Content-Type': 'application/soap+xml'})
        return f


@fixture
def idp(sp_settings, idp_metadata, idp_private_key, sp_metadata):
    return MockIdp(idp_metadata, idp_private_key, sp_metadata)


def test_sso_slo(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'])
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)


def test_sso(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'])
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body})
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)


def test_sso_request_denied(db, app, idp, caplog, sp_settings):
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'], auth_result=False)
    assert url.endswith(reverse('mellon_login'))
    response = app.post(reverse('mellon_login'), params={'SAMLResponse': body})
    if six.PY3:
        assert "status is not success codes: ['urn:oasis:names:tc:SAML:2.0:status:Responder',\
 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text
    else:
        assert "status is not success codes: [u'urn:oasis:names:tc:SAML:2.0:status:Responder',\
 u'urn:oasis:names:tc:SAML:2.0:status:RequestDenied']" in caplog.text


def test_sso_artifact(db, app, caplog, sp_settings, idp_metadata, idp_private_key, rf):
    sp_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    request = rf.get('/')
    sp_metadata = create_metadata(request)
    idp = MockIdp(idp_metadata, idp_private_key, sp_metadata)
    response = app.get(reverse('mellon_login'))
    url, body = idp.process_authn_request_redirect(response['Location'])
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url)
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)
    # force delog
    app.session.flush()
    assert 'dead artifact' not in caplog.text
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url)
    # verify retry login was asked
    assert 'dead artifact' in caplog.text
    assert response.status_code == 302
    assert reverse('mellon_login') in url
    response = response.follow()
    url, body = idp.process_authn_request_redirect(response['Location'])
    reset_caplog(caplog)
    # verify caplog has been cleaned
    assert 'created new user' not in caplog.text
    assert body is None
    assert reverse('mellon_login') in url
    assert 'SAMLart' in url
    acs_artifact_url = url.split('testserver', 1)[1]
    with HTTMock(idp.mock_artifact_resolver()):
        response = app.get(acs_artifact_url)
    assert 'created new user' in caplog.text
    assert 'logged in using SAML' in caplog.text
    assert response['Location'].endswith(sp_settings.LOGIN_REDIRECT_URL)
