import fcntl
import json
import lasso
import logging
import tempfile
from datetime import timedelta

from django.utils.text import slugify
from datetime import datetime

import requests
from xml.etree import ElementTree as ET
import os
import hashlib
import os.path

from django.core.files.storage import default_storage


def truncate_unique(s, length=250):
    if len(s) < length:
        return s
    md5 = hashlib.md5(s.encode('ascii')).hexdigest()
    # we should be the first and last characters from the URL
    l = (length - len(md5)) / 2 - 2  # four additional characters
    assert l > 20
    return s[:l] + '...' + s[-l:] + '_' + md5


def url2filename(url):
    return truncate_unique(slugify(url), 230)


def load_federation_cache(url):
    logger = logging.getLogger(__name__)
    try:
        filename = url2filename(url)
        path = os.path.join('metadata-cache', filename)

        unix_path = default_storage.path(path)
        if not os.path.exists('metadata-cache'):
            os.makedirs('metadata-cache')
        f = open(unix_path, 'w')
        try:
            fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return
        else:
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(unix_path), delete=False) as temp:
                try:
                    # increase modified time by one hour to prevent too many updates
                    st = os.stat(unix_path)
                    os.utime(unix_path, (st.st_atime, st.st_mtime + 3600))
                    response = requests.get(url)
                    response.raise_for_status()
                    temp.write(response.content)
                    temp.flush()
                    os.rename(temp.name, unix_path)
                except:
                    logger.error('Could\'nt fetch %r', url)
                    os.unlink(temp.name)
                finally:
                    fcntl.lockf(f, fcntl.LOCK_UN)
        finally:
            f.close()
    except OSError:
        logger.exception(u"could create the intermediary 'metadata-cache' "
                         "folder")
        return
    except:
        logger.exception(u'failed to load federation from %s', url)


def get_federation_from_url(url, update_cache=False):
    logger = logging.getLogger(__name__)
    filename = url2filename(url)
    path = os.path.join('metadata-cache', filename)
    if not default_storage.exists(path) or update_cache or \
            default_storage.created_time(path) < datetime.now() - timedelta(days=1):
        load_federation_cache(url)
    else:
        logger.warning('federation %s has not been loaded', url)
    return path


def idp_metadata_filepath(entity_id):
    filename = url2filename(entity_id)
    return os.path.join('./metadata-cache', filename)


def idp_settings_filepath(entity_id):
    filename = url2filename(entity_id) + "_settings.json"
    return os.path.join('./metadata-cache', filename)


def idp_metadata_is_cached(entity_id):
    filepath = idp_metadata_filepath(entity_id)
    if not default_storage.exists(filepath):
        return False
    return True


def idp_metadata_is_file(metadata):
    # XXX too restrictive (e.g. 'metadata/http-somemetadataserver-com-md00.xml'
    # could be a file too...)
    # On the opposite, `if "http://" in metadata or "https://" in metadata:" is
    # equally restrictive.
    # Using a URLValidator doesn't seem adequate either.
    if metadata.startswith('/') or metadata.startswith('./'):
        return True


def idp_metadata_needs_refresh(entity_id, update_cache=False):
    filepath = idp_metadata_filepath(entity_id)
    if not default_storage.exists(filepath) or update_cache or \
            default_storage.created_time(filepath) < datetime.now() - timedelta(days=1):
        return True
    return False


def idp_settings_needs_refresh(entity_id, update_cache=False):
    filepath = idp_settings_filepath(entity_id)
    if not default_storage.exists(filepath) or update_cache or \
            default_storage.created_time(filepath) < datetime.now() - timedelta(days=1):
        return True
    return False


def idp_metadata_store(metadata_content):
    entity_id = idp_metadata_extract_entity_id(metadata_content)
    if not entity_id:
        return
    logger = logging.getLogger(__name__)
    filepath = idp_metadata_filepath(entity_id)
    if idp_metadata_needs_refresh(entity_id):
        with open(filepath, 'w') as f:
            try:
                fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                f.write(metadata_content)
                fcntl.lockf(f, fcntl.LOCK_UN)
            except:
                logger.error('Couldn\'t store metadata for EntityID %r',
                        entity_id)
                return
    return filepath


def idp_metadata_load(entity_id):
    logger = logging.getLogger(__name__)
    filepath = idp_metadata_filepath(entity_id)
    if default_storage.exists(filepath):
        logger.info('Loading metadata for EntityID %r', entity_id)
        with open(filepath, 'r') as f:
            return f.read()
    else:
        logger.warning('No metadata file for EntityID %r', entity_id)


def idp_settings_store(idp):
    """
    Stores an IDP settings when loaded from a federation.
    """
    logger = logging.getLogger(__name__)
    entity_id = idp.get('ENTITY_ID')
    filepath = idp_settings_filepath(entity_id)
    idp_settings = {}

    if not entity_id:
        return

    for key, value in idp.items():
        if key not in ('METADATA', 'ENTITY_ID'):
            idp_settings.update({key: value})

    if idp_settings_needs_refresh(entity_id) and idp_settings:
        with open(filepath, 'w') as f:
            try:
                fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                f.write(json.dumps(idp_settings))
                fcntl.lockf(f, fcntl.LOCK_UN)
            except:
                logger.error('Couldn\'t store settings for EntityID %r',
                        entity_id)
                return
    return filepath


def idp_settings_load(entity_id):
    logger = logging.getLogger(__name__)
    filepath = idp_settings_filepath(entity_id)
    if default_storage.exists(filepath):
        logger.info('Loading JSON settings for EntityID %r', entity_id)
        with open(filepath, 'r') as f:
            try:
                idp_settings = json.loads(f.read())
            except:
                logger.warning('Couldn\'t load JSON settings for EntityID %r',
                        entity_id)
            else:
                return idp_settings
    else:
        logger.warning('No JSON settings file for EntityID %r', entity_id)


def idp_metadata_extract_entity_id(metadata_content):
    logger = logging.getLogger(__name__)
    try:
        doc = ET.fromstring(metadata_content)
    except (TypeError, ET.ParseError):
        logger.error(u'METADATA of idp %r is invalid', metadata_content)
        return
    if doc.tag != '{%s}EntityDescriptor' % lasso.SAML2_METADATA_HREF:
        logger.error(u'METADATA of idp %r has no EntityDescriptor root tag',
                metadata_content)
        return
    if not 'entityID' in doc.attrib:
        logger.error(
                u'METADATA of idp %r has no entityID attribute on its root tag',
                metadata_content)
        return
    return doc.attrib['entityID']
