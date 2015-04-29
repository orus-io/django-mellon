from django.conf import global_settings

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'mellon.sqlite3',
    }
}
DEBUG = True
SECRET_KEY='xx'
INSTALLED_APPS = ('mellon', 'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions')
MIDDLEWARE_CLASSES = global_settings.MIDDLEWARE_CLASSES
