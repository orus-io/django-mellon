from django.contrib.sessions.backends.db import SessionStore

from . import db


class SessionStore(db.SessionStore, SessionStore):
    pass
