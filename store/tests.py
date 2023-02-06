import random

import pytest
from django.test import TestCase, TransactionTestCase
from django.utils.crypto import get_random_string
import lipsum

from customers.models import Customer
from store.models import Passwd, FernetKey
from support.functions import encrypt_string, decrypt_string, reencrypt_string


def generate_test_data():
    test_data = {
        "master_key": get_random_string(length=6, allowed_chars="0123456789"),
        "name": lipsum.generate_words(random.randint(1, 3)),
        "url": f"https://www.{get_random_string(length=12)}.com",
        "password": get_random_string(length=32),
        "notes": lipsum.generate_sentences(2),
        "mobile": get_random_string(length=9, allowed_chars="123456789"),
        "address": lipsum.generate_words(3),
    }
    return test_data


# class PasswdTest(TestCase):
class PasswdTest(TransactionTestCase):
    def setUp(self):
        self.test_data = generate_test_data()
        self.master_key = self.test_data["master_key"]

        FernetKey.objects.create()

        # Create Customer
        customer = Customer(
            mobile=self.test_data["mobile"],
            address=self.test_data["address"],
            language="es",
        )
        customer.save(master_key=self.master_key)
        self.customer = customer

        # Create Passwd
        self.passwd = Passwd(
            customer=self.customer,
            name=self.test_data["name"],
            url=self.test_data["url"],
            value=self.test_data["password"],
            notes=self.test_data["notes"],
        )
        self.passwd.save(master_key=self.master_key)

    def test_decrypt_passwd(self):
        decrypted_passwd = decrypt_string(self.passwd.value, self.master_key)
        self.assertEqual(decrypted_passwd, self.test_data["password"])

    def test_decrypt_string_after_refresh_fernet(self):
        old_passwd_value = self.passwd.value
        Passwd.refresh_fernet()
        self.passwd.refresh_from_db()
        self.assertNotEqual(old_passwd_value, self.passwd.value)
        decrypted_passwd = decrypt_string(self.passwd.value, self.master_key)
        self.assertEqual(decrypted_passwd, self.test_data["password"])

    def test_decrypt_string_with_multiple_fernet_keys(self):
        FernetKey.objects.create()
        decrypted_passwd = decrypt_string(self.passwd.value, self.master_key)
        self.assertEqual(decrypted_passwd, self.test_data["password"])
        FernetKey.objects.create()
        decrypted_passwd = decrypt_string(self.passwd.value, self.master_key)
        self.assertNotEqual(decrypted_passwd, self.test_data["password"])

    def test_passwd_update(self):
        new_name = f"new {self.passwd.name}"
        new_url = f'{self.passwd.name.replace(".com", ".org")}'
        new_value = f"{self.passwd.value}*"
        new_notes = f"new {self.passwd.notes}"
        self.passwd.name = new_name
        self.passwd.url = new_url
        self.passwd.value = encrypt_string(new_value, self.master_key)
        self.passwd.notes = new_notes
        self.passwd.save()
        # testing changes persist in database
        self.assertEqual(self.passwd.name, new_name)
        self.assertEqual(self.passwd.url, new_url)
        self.assertEqual(decrypt_string(self.passwd.value, self.master_key), new_value)
        self.assertEqual(self.passwd.notes, new_notes)
