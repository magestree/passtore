# Generated by Django 3.2.9 on 2022-09-30 11:05
import uuid

from cryptography.fernet import Fernet


from django.db import migrations


def create_fernet_key(apps, schema_editor):
    fernet_key_model = apps.get_model("store", "FernetKey")
    fernet_key_model.objects.create(
        key=Fernet.generate_key().decode(encoding="utf-8"),
        uuid=uuid.uuid4().__str__(),
        current=True,
    )


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0006_fernetkey'),
    ]

    operations = [
        migrations.RunPython(create_fernet_key)
    ]
