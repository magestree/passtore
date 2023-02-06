import os
import sys
from django.core.wsgi import get_wsgi_application

sys.path.append(os.getcwd())

os.environ['DJANGO_SETTINGS_MODULE'] = 'passtore.settings'

os.environ.setdefault('LANG', 'en_US.UTF-8')
os.environ.setdefault('LC_ALL', 'en_US.UTF-8')

application = get_wsgi_application()
