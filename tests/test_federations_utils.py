import os
import time

from django.utils.text import slugify
from httmock import HTTMock

from mellon.federation_utils import get_federation_from_url, truncate_unique
from utils import sample_federation_response


def test_mock_fedmd_caching():
    url = u'https://dummy.mdserver/metadata.xml'
    filepath = os.path.join('metadata-cache/', truncate_unique(slugify(url)))

    if os.path.isfile(filepath):
        os.remove(filepath)

    with HTTMock(sample_federation_response):
        tmp = get_federation_from_url(url)

    assert tmp == filepath

    st = os.stat(filepath)

    assert os.path.isfile(filepath)
    assert st.st_mtime < time.time() + 3600

    with HTTMock(sample_federation_response):
        get_federation_from_url(url)
    stnew = os.stat(filepath)

    assert stnew.st_ctime == st.st_ctime
    assert stnew.st_mtime == st.st_mtime

    storig = os.stat(os.path.join('tests', 'federation-sample.xml'))

    assert storig.st_size == st.st_size

    os.remove(filepath)
