from django.apps import apps
from django.contrib import admin

for name, model in dict(apps.all_models['store']).items():
    admin.site.register(model)
