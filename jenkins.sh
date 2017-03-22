#!/bin/sh

set -e

pip install --upgrade setuptools pip
pip install --upgrade pylint pylint-django tox

./getlasso.sh
tox -r

/usr/local/bin/merge-coverage.py -o coverage.xml coverage-*.xml
/usr/local/bin/merge-junit-results.py junit-*.xml >junit.xml
test -f pylint.out && cp pylint.out pylint.out.prev
(pylint -f parseable --rcfile /var/lib/jenkins/pylint.django.rc mellon | tee pylint.out) ||
	/bin/true
test -f pylint.out.prev && (diff pylint.out.prev pylint.out | grep '^[><]' | grep .py) || /bin/true
