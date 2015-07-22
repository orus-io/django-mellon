import pytest

from django.conf import settings
from django.contrib import auth

from mellon.adapters import DefaultAdapter

pytestmark = pytest.mark.django_db

idp = {}
saml_attributes = {
    'name_id_content': 'x'*32,
    'issuer': 'https://idp.example.net/saml/metadata',
    'username': ['foobar'],
    'email': ['test@example.net'],
    'first_name': ['Foo'],
    'last_name': ['Bar'],
    'is_superuser': ['true'],
}

def test_format_username(settings):
    adapter = DefaultAdapter()
    assert adapter.format_username(idp, {}) == None
    assert adapter.format_username(idp, saml_attributes) == ('x'*32 + '@saml')[:30]
    settings.MELLON_USERNAME_TEMPLATE = '{attributes[name_id_content]}'
    assert adapter.format_username(idp, saml_attributes) == ('x'*32)[:30]
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

def test_provision(settings):
    User = auth.get_user_model()
    adapter = DefaultAdapter()
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    user = User(username='xx')
    user.save()
    adapter.provision(user, idp, saml_attributes)
    assert user.first_name == 'Foo'
    assert user.last_name == 'Bar'
    assert user.email == 'test@example.net'
    assert user.is_superuser == False
    User.objects.all().delete()

    settings.MELLON_SUPERUSER_MAPPING = {
        'is_superuser': 'true',
    }
    user = User(username='xx')
    user.save()
    adapter.provision(user, idp, saml_attributes)
    assert user.is_superuser == True
    User.objects.all().delete()

    local_saml_attributes = saml_attributes.copy()
    del local_saml_attributes['email']
    user = User(username='xx')
    user.save()
    adapter.provision(user, idp, local_saml_attributes)
    assert not user.email
    User.objects.all().delete()

    local_saml_attributes = saml_attributes.copy()
    settings.MELLON_ATTRIBUTE_MAPPING = {
        'email': '{attributes[email][0]}',
        'first_name': '{attributes[first_name][0]}',
        'last_name': '{attributes[last_name][0]}',
    }
    local_saml_attributes['first_name'] = [('y' * 32)]
    user = User(username='xx')
    user.save()
    adapter.provision(user, idp, local_saml_attributes)
    assert user.first_name == 'y' * 30
    User.objects.all().delete()
