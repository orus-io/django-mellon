import logging
import re
import time
import datetime
import importlib
from functools import wraps
from xml.etree import ElementTree as ET
import requests

from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
import lasso

from . import app_settings

METADATA = {}

def create_metadata(request):
    entity_id = reverse('mellon_metadata')
    if entity_id not in METADATA:
        login_url = reverse('mellon_login')
        logout_url = reverse('mellon_logout')
        public_keys = []
        for public_key in app_settings.PUBLIC_KEYS:
            if public_key.startswith('/'):
                # clean PEM file
                public_key = ''.join(file(public_key).read().splitlines()[1:-1])
            public_keys.append(public_key)
        name_id_formats = app_settings.NAME_ID_FORMATS
        return render_to_string('mellon/metadata.xml', {
                'entity_id': request.build_absolute_uri(entity_id),
                'login_url': request.build_absolute_uri(login_url),
                'logout_url': request.build_absolute_uri(logout_url),
                'public_keys': public_keys,
                'name_id_formats': name_id_formats,
                'default_assertion_consumer_binding': app_settings.DEFAULT_ASSERTION_CONSUMER_BINDING,
            })
    return METADATA[entity_id]

SERVERS = {}

def create_server(request):
    root = request.build_absolute_uri('/')
    if root not in SERVERS:
        idps = get_idps()
        metadata = create_metadata(request)
        if app_settings.PRIVATE_KEY:
            private_key = app_settings.PRIVATE_KEY
            private_key_password = app_settings.PRIVATE_KEY_PASSWORD
        elif app_settings.PRIVATE_KEYS:
            private_key = app_settings.PRIVATE_KEYS
            private_key_password = None
            if isinstance(private_key, (tuple, list)):
                private_key_password = private_key[1]
                private_key = private_key[0]
        else: # no signature
            private_key = None
            private_key_password = None
        server = lasso.Server.newFromBuffers(metadata,
                private_key_content=private_key,
                private_key_password=private_key_password)
        server.setEncryptionPrivateKeyWithPassword(private_key, private_key_password)
        for key in app_settings.PRIVATE_KEYS:
            password = None
            if isinstance(key, (tuple, list)):
                password = key[1]
                key = key[0]
            server.setEncryptionPrivateKeyWithPassword(key, password)
        for idp in idps:
            if 'METADATA_URL' in idp and 'METADATA' not in idp:
                verify_ssl_certificate = get_setting(
                    idp, 'VERIFY_SSL_CERTIFICATE')
                idp['METADATA'] = requests.get(idp['METADATA_URL'],
                                    verify=verify_ssl_certificate).content
            metadata = idp['METADATA']
            if metadata.startswith('/'):
                metadata = file(metadata).read()
            idp['ENTITY_ID'] = ET.fromstring(metadata).attrib['entityID']
            server.addProviderFromBuffer(lasso.PROVIDER_ROLE_IDP, metadata)
        SERVERS[root] = server
    return SERVERS[root]

def create_login(request):
    server = create_server(request)
    login = lasso.Login(server)
    if not app_settings.PRIVATE_KEY and not app_settings.PRIVATE_KEYS:
        login.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
    return login

def get_idp(entity_id):
    for adapter in get_adapters():
        if hasattr(adapter, 'get_idp'):
            idp = adapter.get_idp(entity_id)
            if idp:
                return idp
    return {}

def get_idps():
    for adapter in get_adapters():
        if hasattr(adapter, 'get_idps'):
            for idp in adapter.get_idps():
                yield idp

def flatten_datetime(d):
    for key, value in d.iteritems():
        if isinstance(value, datetime.datetime):
            d[key] = value.isoformat() + 'Z'
    return d

def iso8601_to_datetime(date_string):
    '''Convert a string formatted as an ISO8601 date into a time_t
       value.

       This function ignores the sub-second resolution'''
    m = re.match(r'(\d+-\d+-\d+T\d+:\d+:\d+)(?:\.\d+)?Z$', date_string)
    if not m:
        raise ValueError('Invalid ISO8601 date')
    tm = time.strptime(m.group(1)+'Z', "%Y-%m-%dT%H:%M:%SZ")
    return datetime.datetime.fromtimestamp(time.mktime(tm))

def to_list(func):
    @wraps(func)
    def f(*args, **kwargs):
        return list(func(*args, **kwargs))
    return f

def import_object(path):
    module, name = path.rsplit('.', 1)
    module = importlib.import_module(module)
    return getattr(module, name)

@to_list
def get_adapters(idp={}):
    idp = idp or {}
    adapters = tuple(idp.get('ADAPTER', ())) + tuple(app_settings.ADAPTER)
    for adapter in adapters:
        yield import_object(adapter)()

def get_values(saml_attributes, name):
    values = saml_attributes.get(name)
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        return (values,)
    return values

def get_setting(idp, name, default=None):
    '''Get a parameter from an IdP specific configuration or from the main
       settings.
    '''
    return idp.get(name) or getattr(app_settings, name, default)

def create_logout(request):
    logger = logging.getLogger(__name__)
    server = create_server(request)
    mellon_session = request.session.get('mellon_session', {})
    entity_id = mellon_session.get('issuer')
    session_index = mellon_session.get('session_index')
    name_id_format = mellon_session.get('name_id_format')
    name_id_content = mellon_session.get('name_id_content')
    name_id_name_qualifier = mellon_session.get('name_id_name_qualifier')
    name_id_sp_name_qualifier = mellon_session.get('name_id_sp_name_qualifier')
    session_dump = render_to_string('mellon/session_dump.xml', {
            'entity_id': entity_id,
            'session_index': session_index,
            'name_id_format': name_id_format,
            'name_id_content': name_id_content,
            'name_id_name_qualifier': name_id_name_qualifier,
            'name_id_sp_name_qualifier': name_id_sp_name_qualifier,
    })
    logger.debug('session_dump %s', session_dump)
    logout = lasso.Logout(server)
    if not app_settings.PRIVATE_KEY:
        logout.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
    logout.setSessionFromDump(session_dump)
    return logout
