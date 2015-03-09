try:
    import lasso
except ImportError:
    print '***** django-mellon needs the Python binding for the lasso library, *****'
    print '***** look on http://lasso.entrouvert.org/download/ to obtain it    *****'
    raise
