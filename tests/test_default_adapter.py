import pytest
import re
import lasso
from multiprocessing.pool import ThreadPool

from django.contrib import auth
from django.db import connection

from mellon.adapters import DefaultAdapter
from mellon.backends import SAMLBackend

pytestmark = pytest.mark.django_db

idp = {
    'METADATA': open('tests/metadata.xml').read(),
}
saml_attributes = {
    'name_id_format': lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
    'name_id_content': 'x' * 32,
    'issuer': 'http://idp5/metadata',
    'username': ['foobar'],
    'email': ['test@example.net'],
    'first_name': ['Foo'],
    'last_name': ['Bar'],
    'is_superuser': ['true'],
    'group': ['GroupA', 'GroupB', 'GroupC'],
}


def test_format_username(settings):
    adapter = DefaultAdapter()
    assert adapter.format_username(idp, {}) is None
    assert adapter.format_username(idp, saml_attributes) == ('x' * 32 + '@saml')[:30]
    settings.MELLON_USERNAME_TEMPLATE = '{attributes[name_id_content]}'
    assert adapter.format_username(idp, saml_attributes) == ('x' * 32)[:30]
    settings.MELLON_USERNAME_TEMPLATE = '{attributes[username][0]}'
    assert adapter.format_username(idp, saml_attributes) == 'foobar'


def test_lookup_user(settings):
    User = auth.get_user_model()
    adapter = DefaultAdapter()
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is not None

    user2 = adapter.lookup_user(idp, saml_attributes)
    assert user.id == user2.id

    User.objects.all().delete()
    assert User.objects.count() == 0

    settings.MELLON_PROVISION = False
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is None
    assert User.objects.count() == 0


def test_lookup_user_transaction(transactional_db, concurrency):
    adapter = DefaultAdapter()
    p = ThreadPool(concurrency)

    def f(i):
        # sqlite has a default lock timeout of 5s seconds between different access to the same in
        # memory DB
        if connection.vendor == 'sqlite':
            connection.cursor().execute('PRAGMA busy_timeout = 400000')
        try:
            return adapter.lookup_user(idp, saml_attributes)
        finally:
            connection.close()
    users = p.map(f, range(concurrency))

    assert len(users) == concurrency
    assert len(set(user.pk for user in users)) == 1


def test_provision_user_attributes(settings, django_user_model, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.username == 'x' * 30
    assert user.first_name == 'Foo'
    assert user.last_name == 'Bar'
    assert user.email == 'test@example.net'
    assert user.is_superuser is False
    assert user.is_staff is False
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'set field first_name' in caplog.text
    assert 'set field last_name' in caplog.text
    assert 'set field email' in caplog.text


def test_provision_user_groups(settings, django_user_model, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_GROUP_ATTRIBUTE = 'group'
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.groups.count() == 3
    assert set(user.groups.values_list('name', flat=True)) == set(saml_attributes['group'])
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'adding group GroupA' in caplog.text
    assert 'adding group GroupB' in caplog.text
    assert 'adding group GroupC' in caplog.text
    saml_attributes2 = saml_attributes.copy()
    saml_attributes2['group'] = ['GroupB', 'GroupC']
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes2)
    assert user.groups.count() == 2
    assert set(user.groups.values_list('name', flat=True)) == set(saml_attributes2['group'])
    assert len(caplog.records) == 5
    assert 'removing group GroupA' in caplog.records[-1].message


def test_provision_is_superuser(settings, django_user_model, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_SUPERUSER_MAPPING = {
        'is_superuser': 'true',
    }
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.is_superuser is True
    assert user.is_staff is True
    assert 'flag is_staff and is_superuser added' in caplog.text
    user = SAMLBackend().authenticate(saml_attributes=saml_attributes)
    assert user.is_superuser is True
    assert user.is_staff is True
    assert not 'flag is_staff and is_superuser removed' in caplog.text


def test_provision_absent_attribute(settings, django_user_model, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    local_saml_attributes = saml_attributes.copy()
    del local_saml_attributes['email']
    user = SAMLBackend().authenticate(saml_attributes=local_saml_attributes)
    assert not user.email
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert re.search(r'invalid reference.*email', caplog.text)
    assert 'set field first_name' in caplog.text
    assert 'set field last_name' in caplog.text


def test_provision_long_attribute(settings, django_user_model, caplog):
    settings.MELLON_IDENTITY_PROVIDERS = [idp]
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    local_saml_attributes = saml_attributes.copy()
    local_saml_attributes['first_name'] = [('y' * 32)]
    user = SAMLBackend().authenticate(saml_attributes=local_saml_attributes)
    assert user.first_name == 'y' * 30
    assert len(caplog.records) == 4
    assert 'created new user' in caplog.text
    assert 'set field first_name' in caplog.text
    assert 'to value %r ' % (u'y' * 30) in caplog.text
    assert 'set field last_name' in caplog.text
    assert 'set field email' in caplog.text


def test_lookup_user_transient_with_email(private_settings):
    private_settings.MELLON_TRANSIENT_FEDERATION_ATTRIBUTE = 'email'
    User = auth.get_user_model()
    adapter = DefaultAdapter()
    saml_attributes2 = saml_attributes.copy()
    saml_attributes2['name_id_format'] = lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT
    assert User.objects.count() == 0
    user = adapter.lookup_user(idp, saml_attributes2)
    assert user is not None
    assert user.saml_identifiers.count() == 1
    assert user.saml_identifiers.first().name_id == saml_attributes2['email'][0]

    user2 = adapter.lookup_user(idp, saml_attributes2)
    assert user.id == user2.id

    User.objects.all().delete()
    assert User.objects.count() == 0

    private_settings.MELLON_PROVISION = False
    user = adapter.lookup_user(idp, saml_attributes)
    assert user is None
    assert User.objects.count() == 0
