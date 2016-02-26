from lxml import etree as ET


def assert_xml_constraints(content, constraint, namespaces={}):
    d = ET.fromstring(content)
    def check(constraint, prefix=''):
        path, count = constraint[:2]
        path = prefix + path
        if not count is None:
            l = d.xpath(path, namespaces=namespaces)
            assert len(l) == count, 'len(xpath(%s)) is not %s but %s' % (path, count, len(l))
        if len(constraint) > 2:
            for constraint in constraint[2:]:
                check(constraint, prefix=path)
    check(constraint)
