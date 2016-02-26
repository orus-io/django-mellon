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
