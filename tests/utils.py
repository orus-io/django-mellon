from httmock import all_requests, response


@all_requests
def error_500(url, request):
    return response(500, reason='Internal Server Error', request=request)


@all_requests
def html_response(url, request):
    return response(200, '<html></html>', headers={'content-type': 'text/html'}, request=request)


@all_requests
def metadata_response(url, request):
    return response(200, content=open('tests/metadata.xml').read())


def reset_caplog(cap):
    cap.handler.stream.truncate(0)
    cap.handler.records = []
