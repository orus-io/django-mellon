import logging
import pytest
import django_webtest


@pytest.fixture
def app(request):
    wtm = django_webtest.WebTestMixin()
    wtm._patch_settings()
    request.addfinalizer(wtm._unpatch_settings)
    return django_webtest.DjangoTestApp()


@pytest.fixture
def concurrency(settings):
    '''Select a level of concurrency based on the db, sqlite3 is less robust
       thant postgres due to its transaction lock timeout of 5 seconds.
    '''
    if 'sqlite' in settings.DATABASES['default']['ENGINE']:
        return 20
    else:
        return 100


@pytest.fixture
def private_settings(request):
    import django.conf
    from django.conf import UserSettingsHolder
    old = django.conf.settings._wrapped
    django.conf.settings._wrapped = UserSettingsHolder(old)

    def finalizer():
        django.conf.settings._wrapped = old
    request.addfinalizer(finalizer)
    return django.conf.settings


@pytest.fixture
def caplog(caplog):
    import py.io
    caplog.set_level(logging.INFO)
    caplog.handler.stream = py.io.TextIO()
    caplog.handler.records = []
    return caplog
