# Django settings.py for vulnerable app fixture (BF-005)

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    # BF-005: DEFAULT_PERMISSION_CLASSES is missing, meaning it defaults to AllowAny.
}
