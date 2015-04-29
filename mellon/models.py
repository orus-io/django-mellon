from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

class UserSAMLIdentifier(models.Model):
    user    = models.ForeignKey(
                 verbose_name=_('user'),
                 to=settings.AUTH_USER_MODEL,
                 related_name='saml_identifiers')
    issuer  = models.TextField(
                 verbose_name=_('Issuer'))
    name_id = models.TextField(
                 verbose_name=_('SAML identifier'))
    created = models.DateTimeField(
                 verbose_name=_('created'),
                 auto_now_add=True)

    class Meta:
        verbose_name = _('user SAML identifier')
        verbose_name_plural = _('users SAML identifiers')
        unique_together = (('issuer', 'name_id'),)
