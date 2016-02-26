import pytest
import mock
import lasso
from urlparse import parse_qs, urlparse
import base64

from django.core.urlresolvers import reverse
from django.core.exceptions import ImproperlyConfigured
from django.utils.http import urlencode

from xml_utils import assert_xml_constraints


def test_null_character_on_samlresponse_post(app):
    app.post(reverse('mellon_login'), {'SAMLResponse': '\x00'}, status=400)


def test_metadata(private_settings, client):
    ns = {
        'sm': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }
    private_settings.MELLON_PUBLIC_KEYS = ['xxx', '/yyy']
    private_settings.MELLON_NAME_ID_FORMATS = [lasso.SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED]
    private_settings.MELLON_DEFAULT_ASSERTION_CONSUMER_BINDING = 'artifact'
    private_settings.MELLON_ORGANIZATION = {
        'NAMES': [
            'Foobar',
            {
                'LABEL': 'FoobarEnglish',
                'LANG': 'en',
            }
        ],
        'DISPLAY_NAMES': [
            'Foobar',
            {
                'LABEL': 'FoobarEnglish',
                'LANG': 'en',
            }
        ],
        'URLS': [
            'http://foobar.com/',
            {
                'URL': 'http://foobar.com/en/',
                'LANG': 'en',
            }
        ],
    }
    private_settings.MELLON_CONTACT_PERSONS = [
        {
            'CONTACT_TYPE': 'administrative',
            'COMPANY': 'FooBar',
            'GIVENNAME': 'John',
            'SURNAME': 'Doe',
            'EMAIL_ADDRESSES': [
                'john.doe@foobar.com',
                'john.doe@personal-email.com',
            ],
            'TELEPHONE_NUMBERS': [
                '+abcd',
                '+1234',
            ],
        },
        {
            'CONTACT_TYPE': 'technical',
            'COMPANY': 'FooBar2',
            'GIVENNAME': 'John',
            'SURNAME': 'Doe',
            'EMAIL_ADDRESSES': [
                'john.doe@foobar.com',
                'john.doe@personal-email.com',
            ],
            'TELEPHONE_NUMBERS': [
                '+abcd',
                '+1234',
            ],
        },
    ]

    with mock.patch('mellon.utils.file', mock.mock_open(read_data='BEGIN\nyyy\nEND'), create=True):
        response = client.get('/metadata/')
    assert_xml_constraints(
        response.content,
        ('/sm:EntityDescriptor[@entityID="http://testserver/metadata/"]', 1,
         ('/*', 4),
         ('/sm:SPSSODescriptor', 1,
          ('/*', 6),
          ('/sm:NameIDFormat', 1),
          ('/sm:SingleLogoutService', 1),
          ('/sm:AssertionConsumerService', None,
           ('[@isDefault="true"]', None,
            ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"]', 1),
            ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]', 0)),
           ('[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]', 1)),
          ('/sm:KeyDescriptor/ds:KeyInfo/ds:X509Data', 2,
           ('/ds:X509Certificate', 2),
           ('/ds:X509Certificate[text()="xxx"]', 1),
           ('/ds:X509Certificate[text()="yyy"]', 1))),
         ('/sm:Organization', 1,
          ('/sm:OrganizationName', 2),
          ('/sm:OrganizationName[text()="Foobar"]', 1),
          ('/sm:OrganizationName[text()="FoobarEnglish"]', 1,
           ('[@xml:lang="en"]', 1)),
          ('/sm:OrganizationDisplayName', 2),
          ('/sm:OrganizationDisplayName[text()="Foobar"]', 1),
          ('/sm:OrganizationDisplayName[text()="FoobarEnglish"]', 1,
           ('[@xml:lang="en"]', 1)),
          ('/sm:OrganizationURL', 2),
          ('/sm:OrganizationURL[text()="http://foobar.com/"]', 1),
          ('/sm:OrganizationURL[text()="http://foobar.com/en/"]', 1,
           ('[@xml:lang="en"]', 1))),
         ('/sm:ContactPerson', 2,
          ('[@contactType="technical"]', 1),
          ('[@contactType="administrative"]', 1))),
        namespaces=ns)


def test_sp_initiated_login_improperly_configured(private_settings, client):
    with pytest.raises(ImproperlyConfigured):
        client.get('/login/')


def test_sp_initiated_login_improperly_configured2(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = []
    response = client.get('/login/')
    assert response.status_code == 400
    assert 'no idp found' in response.content


def test_sp_initiated_login_discovery_service(private_settings, client):
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://disco?')
    assert params == {'return': ['http://testserver/login/'],
                      'nodisco': ['1']}


def test_sp_initiated_login_discovery_service_passive(private_settings, client):
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/?passive=1')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://disco?')
    assert params == {'isPassive': ['true'],
                      'return': ['http://testserver/login/'],
                      'nodisco': ['1']}


def test_sp_initiated_login_discovery_service_nodisco(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = []
    private_settings.MELLON_DISCOVERY_SERVICE_URL = 'https://disco'
    response = client.get('/login/?nodisco=1')
    assert response.status_code == 400
    assert 'no idp found' in response.content


def test_sp_initiated_login(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    response = client.get('/login/?next=%2Fwhatever')
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://cresson.entrouvert.org/idp/saml2/sso?')
    assert set(params.keys()) == set(['SAMLRequest', 'RelayState'])
    assert len(params['SAMLRequest']) == 1
    assert base64.b64decode(params['SAMLRequest'][0])
    assert params['RelayState'] == ['/whatever']


def test_sp_initiated_login_chosen(private_settings, client):
    private_settings.MELLON_IDENTITY_PROVIDERS = [{
        'METADATA': open('tests/metadata.xml').read(),
    }]
    qs = urlencode({
        'entityID': 'https://cresson.entrouvert.org/idp/saml2/metadata',
        'next': '/whatever',
    })
    response = client.get('/login/?' + qs)
    assert response.status_code == 302
    params = parse_qs(urlparse(response['Location']).query)
    assert response['Location'].startswith('https://cresson.entrouvert.org/idp/saml2/sso?')
    assert set(params.keys()) == set(['SAMLRequest', 'RelayState'])
    assert len(params['SAMLRequest']) == 1
    assert base64.b64decode(params['SAMLRequest'][0])
    assert params['RelayState'] == ['/whatever']