import base64
import datetime
import threading
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django_cryptography.fields import encrypt
from django.utils.translation import ugettext_lazy as _

from passtore.settings import TESTING
from support.functions import encrypt_string, decrypt_string, reencrypt_string, get_expire_time_code
from support.emails import send_email


class Customer(User):
    mobile = models.CharField('Mobile', blank=True, null=True, max_length=16)
    address = models.CharField('Address', blank=True, null=True, max_length=255)
    language = models.CharField('Language', max_length=8, blank=True, null=True)
    test_passwd = encrypt(models.TextField('Test passwd', blank=True, null=True))
    secret_key = models.CharField(max_length=88, db_index=True, blank=True, null=True)
    uuid = models.CharField('UUID', max_length=36, null=True, blank=True)

    def get_master_key(self):
        # This only works for numbers between 0 and 999999
        for master_key in range(1000000):
            if self.validate_master_key(master_key):
                return master_key
        return None

    @staticmethod
    def refresh_secret_key():
        part_1 = uuid.uuid4().__str__()
        part_2 = uuid.uuid4().__str__()
        secret_key = base64.b64encode(
            f"{part_1}{part_2}".replace("-", "").encode()
        ).decode()
        return secret_key

    @property
    def default_api_key(self):
        return self.apikey_set.filter(active=True, name="default").first()

    def validate_master_key(self, master_key):
        return decrypt_string(self.test_passwd, master_key) is not None

    def reencrypt_test_passwd(self, old_master_key, new_master_key):
        self.test_passwd = reencrypt_string(self.test_passwd, old_master_key, new_master_key)
        self.save()

    def update_master_key(self, old_master_key, new_master_key):
        # 1 - Set all related passwords as unavailable
        self.passwd_set.update(available=False)
        # 2 - Reencrypt test_passwd
        self.reencrypt_test_passwd(old_master_key, new_master_key)
        # 3 - Reencrypt all passwords
        for passwd in self.passwd_set.all():
            passwd.value = reencrypt_string(passwd.value, old_master_key, new_master_key)
            passwd.available = True  # Restore passwd availability
            passwd.save()

    def notify_registration(self):
        send_email(
            app=self._meta.app_label,
            template="registration",
            subject="Se ha registrado correctamente",
            context={},
            target=self.email,
        )

    def save(self, master_key=None, *args, **kwargs):
        creating = False
        if self._state.adding:
            creating = True
            if not master_key:
                raise AttributeError('master_key is required to create a Customer object')
            self.uuid = uuid.uuid4().__str__()
            self.test_passwd = encrypt_string(get_random_string(12), master_key)
            self.secret_key = self.refresh_secret_key()
            # Don't notify customer creation when testing
            if not TESTING:
                self.notify_registration()
        super(Customer, self).save(*args, **kwargs)
        if creating:
            ApiKey.objects.create(customer=self)


class RecoverCode(models.Model):
    code = models.CharField(max_length=6)
    email = models.EmailField()
    expire = models.DateTimeField()

    def __str__(self):
        return self.code

    @classmethod
    def delete_expired_codes(cls):
        cls.objects.filter(expire__lt=datetime.datetime.utcnow()).delete()

    @classmethod
    def generate_code(cls):
        # Delete expired_codes
        thread = threading.Thread(
            target=cls.delete_expired_codes,
            args=(),
        )
        thread.start()
        # Generate and return new, unused code
        while True:
            code = str(uuid.uuid4().int)[:6]
            if not RecoverCode.objects.filter(code=code):
                break
        return code

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.code = self.generate_code()
            self.expire = get_expire_time_code()
        super(RecoverCode, self).save(*args, **kwargs)


class ApiKey(models.Model):
    name = models.CharField(max_length=32, default="default")
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    value = models.CharField(max_length=44, db_index=True)
    active = models.BooleanField(default=True)

    @property
    def active_access_token(self):
        return self.accesstoken_set.filter(active=True).first()

    @staticmethod
    def generate_value():
        value = base64.b64encode(
            uuid.uuid4().__str__().replace("-", "").encode()
        ).decode()
        return value

    def save(self, *args, **kwargs):
        creating = False
        if self._state.adding:
            creating = True
            self.value = self.generate_value()
        super(ApiKey, self).save(*args, **kwargs)
        if creating:
            AccessToken.objects.create(api_key=self)


class AccessToken(models.Model):
    api_key = models.ForeignKey(ApiKey, on_delete=models.CASCADE)
    value = models.CharField(max_length=172, db_index=True)
    active = models.BooleanField(default=True)

    @property
    def authorization_bearer(self):
        return {"Authorization": f"Bearer {self.value}"}

    @staticmethod
    def generate_value():
        part_1 = uuid.uuid4().__str__()
        part_2 = uuid.uuid4().__str__()
        part_3 = uuid.uuid4().__str__()
        part_4 = uuid.uuid4().__str__()
        value = base64.b64encode(
            f"{part_1}{part_2}{part_3}{part_4}".replace("-", "").encode()
        ).decode()
        return value

    def save(self, *args, **kwargs):
        if self._state.adding:
            self.value = self.generate_value()
        super(AccessToken, self).save(*args, **kwargs)
        # Only one AccessToken could be active per ApiKey
        self.api_key.accesstoken_set.exclude(pk=self.pk).delete()


class Permission(models.Model):
    name = models.CharField(max_length=64)


class ApiKeyPermission(models.Model):
    api_key = models.ForeignKey(ApiKey, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)