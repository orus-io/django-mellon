from django.contrib.auth.backends import ModelBackend

from . import utils


class SAMLBackend(ModelBackend):
    def authenticate(self, saml_attributes):
        if not 'issuer' in saml_attributes:
            return
        idp = utils.get_idp(saml_attributes['issuer'])
        adapters = utils.get_adapters(idp)
        for adapter in adapters:
            if not hasattr(adapter, 'authorize'):
                continue
            if not adapter.authorize(idp, saml_attributes):
                return False
        for adapter in adapters:
            if not hasattr(adapter, 'lookup_user'):
                continue
            user = adapter.lookup_user(idp, saml_attributes)
            if user:
                break
        for adapter in adapters:
            if not hasattr(adapter, 'provision'):
                continue
            adapter.provision(user, idp, saml_attributes)
        return user
