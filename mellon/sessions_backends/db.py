from django.contrib.sessions.backends.db import SessionStore

from mellon import utils


class SessionStore(SessionStore):
    def get_session_not_on_or_after(self):
        session_not_on_or_after = self.get('mellon_session', {}).get('session_not_on_or_after')
        if session_not_on_or_after:
            return utils.iso8601_to_datetime(session_not_on_or_after)
        return None

    def get_expiry_age(self, **kwargs):
        session_not_on_or_after = self.get_session_not_on_or_after()
        if session_not_on_or_after and 'expiry' not in kwargs:
            kwargs['expiry'] = session_not_on_or_after
        return super(SessionStore, self).get_expiry_age(**kwargs)

    def get_expiry_date(self, **kwargs):
        session_not_on_or_after = self.get_session_not_on_or_after()
        if session_not_on_or_after and 'expiry' not in kwargs:
            kwargs['expiry'] = session_not_on_or_after
        return super(SessionStore, self).get_expiry_date(**kwargs)
