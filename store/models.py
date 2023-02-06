import datetime
import re
import uuid
from cryptography.fernet import Fernet
from django.apps import apps
from django.db import models
from django_cryptography.fields import encrypt
from urllib.parse import urlparse

from store.processor import FileReader
from support.functions import encrypt_string, fernet_reencrypt_string


class FernetKey(models.Model):
    key = encrypt(models.TextField())
    uuid = models.CharField("UUID", max_length=36, null=True, blank=True)

    @classmethod
    def get_possible_fernet_keys(cls):
        """Return all possible fernet_keys, ensure that there are a maximum of two"""
        fernet_keys = list(cls.objects.order_by("-id").values_list("key", flat=True))
        if 1 <= len(fernet_keys) <= 2:
            return fernet_keys
        return []

    @classmethod
    def get_current_fernet_key(cls):
        return cls.objects.order_by("-id").first().key

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.key = Fernet.generate_key().decode(encoding="utf-8")
            self.uuid = uuid.uuid4().__str__()
        super(FernetKey, self).save(*args, **kwargs)


class Container(models.Model):
    customer = models.ForeignKey("customers.Customer", on_delete=models.CASCADE)
    name = models.CharField("Container", max_length=64)
    uuid = models.CharField("UUID", max_length=36, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.uuid = uuid.uuid4().__str__()
        super(Container, self).save(*args, **kwargs)


class Passwd(models.Model, FileReader):
    customer = models.ForeignKey("customers.Customer", on_delete=models.CASCADE)
    container = models.ForeignKey(Container, blank=True, null=True, on_delete=models.SET_NULL)
    name = models.CharField("Name", max_length=64, blank=True, null=True)
    url = models.CharField("URL", max_length=512)
    website = models.CharField("Website", max_length=512, blank=True, null=True)
    value = encrypt(models.TextField("Value"))
    notes = models.TextField("Notes", blank=True, null=True)
    available = models.BooleanField("Available", default=True)
    uuid = models.CharField("UUID", max_length=36, null=True, blank=True)

    @staticmethod
    def validate_master_key_format(master_key):
        pat = re.compile(r"^[0-9]{6}$")
        if re.fullmatch(pat, master_key):
            return True
        return False

    @classmethod
    def get_passwds_from_url(cls, url):
        website = urlparse(url).hostname
        if website:
            return cls.objects.filter(website=website).values("")
        return None

    @classmethod
    def refresh_fernet(cls):
        new_fernet_key = FernetKey.objects.create()
        for passwd in cls.objects.all():
            new_value = fernet_reencrypt_string(passwd.value)
            passwd.value = new_value
            passwd.save()
        customer_model = apps.get_model("customers", "Customer")
        for customer in customer_model.objects.all():
            new_value = fernet_reencrypt_string(customer.test_passwd)
            customer.test_passwd = new_value
            customer.save()
        FernetKey.objects.exclude(id=new_fernet_key.id).delete()

    def save(self, master_key=None, *args, **kwargs):
        self.website = urlparse(self.url).hostname
        if self._state.adding:
            if not master_key:
                raise AttributeError('master_key is required to create a Passwd object')
            # Rewrite value field with encryption
            self.value = encrypt_string(self.value, master_key)
            self.uuid = uuid.uuid4().__str__()
        super(Passwd, self).save(*args, **kwargs)


class SharedPasswd(models.Model):
    passwd = models.ForeignKey(Passwd, on_delete=models.CASCADE)
    customer_email = models.EmailField()
    shared_value = encrypt(models.TextField())
    accepted = models.BooleanField(default=False)
    uuid = models.CharField("UUID", max_length=36, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.uuid = uuid.uuid4().__str__()
        super(SharedPasswd, self).save(*args, **kwargs)


class Identifier(models.Model):
    passwd = models.ForeignKey(Passwd, on_delete=models.CASCADE)
    key = models.CharField("Key", blank=True, null=True, max_length=64)
    value = models.CharField("Value", max_length=255)
    uuid = models.CharField("UUID", max_length=36, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.uuid = uuid.uuid4().__str__()
        super(Identifier, self).save(*args, **kwargs)
