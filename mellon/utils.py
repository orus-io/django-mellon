import re
import time
import datetime
import importlib
from functools import wraps
from xml.etree import ElementTree as ET

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
                public_key = file(public_key).read()
            public_keys.append(public_key)
        name_id_formats = app_settings.NAME_ID_FORMATS
        return render_to_string('mellon/metadata.xml', {
                'entity_id': request.build_absolute_uri(entity_id),
                'login_url': request.build_absolute_uri(login_url),
                'logout_url': request.build_absolute_uri(logout_url),
                'public_keys': public_keys,
                'name_id_formats': name_id_formats,
            })
    return METADATA[entity_id]

SERVERS = {}

def create_server(request):
    root = request.build_absolute_uri('/')
    if root not in SERVERS:
        idps = app_settings.IDENTITY_PROVIDERS
        metadata = create_metadata(request)
        server = lasso.Server.newFromBuffers(metadata,
                private_key_content=app_settings.PRIVATE_KEY,
                private_key_password=app_settings.PRIVATE_KEY_PASSWORD)
        for idp in idps:
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
    if not app_settings.PRIVATE_KEY:
        login.setSignatureHint(lasso.PROFILE_SIGNATURE_HINT_FORBID)
    return login

def get_idp(entity_id):
    for idp in app_settings.IDENTITY_PROVIDERS:
        if idp['ENTITY_ID'] == entity_id:
            return idp

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
def get_adapters(idp):
    idp = idp or {}
    adapters = idp.get('ADAPTER') or app_settings.ADAPTER
    for adapter in adapters:
        yield import_object(adapter)()

def get_values(saml_attributes, name):
    values = saml_attributes.get(name)
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        return (values,)
    return values



def get_parameter(idp, name):
    return idp.get(name) or getattr(app_settings, name)
