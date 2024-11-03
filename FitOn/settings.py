import os
from pathlib import Path
from datetime import timedelta
import boto3
import json

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


def get_secrets():
    client = boto3.client("secretsmanager", region_name="us-west-2")
    response = client.get_secret_value(SecretId="googleFit_credentials")
    response = json.loads(response["SecretString"])
    GOOGLEFIT_CLIENT_ID = response.get("GOOGLEFIT_CLIENT_ID")
    GOOGLEFIT_CLIENT_SECRET = response.get("GOOGLEFIT_CLIENT_SECRET")
    return (GOOGLEFIT_CLIENT_ID, GOOGLEFIT_CLIENT_SECRET)


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-iqw@@a4osoerv=_))5ipw&kthcyr@v55xwz#=sse!13()+s#l_"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

SCOPES = [
    "https://www.googleapis.com/auth/fitness.activity.read",
    "https://www.googleapis.com/auth/fitness.body.read",
    "https://www.googleapis.com/auth/fitness.heart_rate.read",
    "https://www.googleapis.com/auth/fitness.sleep.read",
    "https://www.googleapis.com/auth/fitness.blood_glucose.read",
    "https://www.googleapis.com/auth/fitness.blood_pressure.read",
    "https://www.googleapis.com/auth/fitness.body_temperature.read",
    "https://www.googleapis.com/auth/fitness.location.read",
    "https://www.googleapis.com/auth/fitness.nutrition.read",
    "https://www.googleapis.com/auth/fitness.oxygen_saturation.read",
    "https://www.googleapis.com/auth/fitness.reproductive_health.read",
]

GOOGLEFIT_PROJECT_ID = "dulcet-coast-387705"
GOOGLEFIT_TOKEN_URI = "https://accounts.google.com/o/oauth2/token"
GOOGLEFIT_CLIENT_ID = get_secrets()[0]
GOOGLEFIT_CLIENT_SECRET = get_secrets()[1]

BASE_URL = (
    "http://127.0.0.1:8000"
    if DEBUG
    else "http://fiton-dev-without-template.us-west-2.elasticbeanstalk.com"
)
# BASE_URL = "fiton-dev-without-template.us-west-2.elasticbeanstalk.com"

REDIRECT_URI = os.getenv("REDIRECT_URL", BASE_URL + "/callback/")

GOOGLEFIT_CLIENT_CONFIG = {
    "web": {
        "client_id": GOOGLEFIT_CLIENT_ID,
        "project_id": GOOGLEFIT_PROJECT_ID,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": GOOGLEFIT_CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI],
    }
}

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    "FitOn",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "storages",  # Add this line for S3 storage
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "FitOn.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "FitOn" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "FitOn.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# SESSION_ENGINE = 'django_dynamodb_sessions.backends.dynamodb'
# DYNAMODB_SESSIONS_TABLE_NAME = 'django-user-sessions'
# SESSION_SAVE_EVERY_REQUEST = True


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# AWS S3 settings
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_STORAGE_BUCKET_NAME = "fiton-static-files"
AWS_S3_REGION_NAME = "us-west-2"

AWS_S3_CUSTOM_DOMAIN = f"{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com"
AWS_DEFAULT_ACL = None
AWS_S3_OBJECT_PARAMETERS = {
    "CacheControl": "max-age=86400",
}

AWS_LOCATION = "static"

# Static files (CSS, JavaScript, Images)
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
# STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/{AWS_LOCATION}/"
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static'] 

STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

# Media files
MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/media/"
DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

PASSWORD_RESET_TIMEOUT = timedelta(minutes=5).total_seconds()
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "fiton.notifications@gmail.com"
EMAIL_HOST_PASSWORD = "usfb imrp rhyq npif"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
# For google redirection
# SECURE_SSL_REDIRECT = True
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
