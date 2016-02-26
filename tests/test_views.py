from django.core.urlresolvers import reverse

def test_null_character_on_samlresponse_post(app):
    app.post(reverse('mellon_login'), {'SAMLResponse': '\x00'}, status=400)
