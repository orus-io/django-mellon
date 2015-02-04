import logging

from django.core.exceptions import PermissionDenied
from django.contrib import auth
from django.contrib.auth.models import Group

from . import utils, app_settings

log = logging.getLogger(__name__)

class DefaultAdapter(object):
    def get_idp(self, entity_id):
        '''Find the first IdP definition matching entity_id'''
        for idp in app_settings.IDENTITY_PROVIDERS:
            if entity_id in idp['ENTITY_ID']:
                return idp

    def authorize(self, idp, saml_attributes):
        if not idp:
            return False
        required_classref = utils.get_setting(idp, 'AUTHN_CLASSREF')
        if required_classref:
            given_classref = saml_attributes['authn_context_class_ref']
            if given_classref is None or \
                    given_classref not in required_classref:
                raise PermissionDenied
        return True

    def format_username(self, idp, saml_attributes):
        realm = utils.get_setting(idp, 'REALM')
        username_template = utils.get_setting(idp, 'USERNAME_TEMPLATE')
        try:
            username = unicode(username_template).format(
                realm=realm, attributes=saml_attributes, idp=idp)
        except ValueError:
            log.error('invalid username template %r'. username_template)
        except (AttributeError, KeyError, IndexError), e:
            log.error('invalid reference in username template %r: %s',
                    username_template, e)
        except Exception, e:
            log.exception('unknown error when formatting username')
        else:
            return username

    def lookup_user(self, idp, saml_attributes):
        User = auth.get_user_model()
        username = self.format_username(idp, saml_attributes)
        if not username:
            return None
        provision = utils.get_setting(idp, 'PROVISION')
        if provision:
            user, created = User.objects.get_or_create(username=username)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return
        return user

    def provision(self, user, idp, saml_attributes):
        self.provision_attribute(user, idp, saml_attributes)
        self.provision_superuser(user, idp, saml_attributes)
        self.provision_groups(user, idp, saml_attributes)

    def provision_attribute(self, user, idp, saml_attributes):
        realm = utils.get_setting(idp, 'REALM')
        attribute_mapping = utils.get_setting(idp, 'ATTRIBUTE_MAPPING')
        for field, tpl in attribute_mapping.iteritems():
            try:
                value = unicode(tpl).format(realm=realm, attributes=saml_attributes, idp=idp)
            except ValueError:
                log.warning('invalid attribute mapping template %r', tpl)
            except (AttributeError, KeyError, IndexError, ValueError), e:
                log.warning('invalid reference in attribute mapping template %r: %s', tpl, e)
            else:
                setattr(user, field, value)

    def provision_superuser(self, user, idp, saml_attributes):
        superuser_mapping = utils.get_setting(idp, 'SUPERUSER_MAPPING')
        if not superuser_mapping:
            return
        for key, values in superuser_mapping.iteritems():
            if key in saml_attributes:
                if not isinstance(values, (tuple, list)):
                    values = [values]
                values = set(values)
                attribute_values = saml_attributes[key]
                if not isinstance(attribute_values, (tuple, list)):
                    attribute_values = [attribute_values]
                attribute_values = set(attribute_values)
                if attribute_values & values:
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()
                    break
        else:
            if user.is_superuser:
                user.is_superuser = False
                user.save()

    def provision_groups(self, user, idp, saml_attributes):
        group_attribute = utils.get_setting(idp, 'GROUP_ATTRIBUTE')
        create_group = utils.get_setting(idp, 'CREATE_GROUP')
        if group_attribute in saml_attributes:
            values = saml_attributes[group_attribute]
            if not isinstance(values, (list, tuple)):
                values = [values]
            groups = []
            for value in set(values):
                if create_group:
                    group, created = Group.objects.get_or_create(name=value)
                else:
                    try:
                        group = Group.objects.get(name=value)
                    except Group.DoesNotExist:
                        continue
                groups.append(group)
            user.groups = groups
