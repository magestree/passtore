import datetime
import json
import random

# from django.test import Client
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase


from store.models import Passwd, FernetKey
from customers.models import Customer


test_passwd = {
    "name": "Passtore",
    "container": {},
    "url": "https://www.passtore.com",
    "value": "Ipvce880920",
    "notes": "This is a note for this password.",
    "identifiers": [
        {"key": "email", "value": "erickmhq@gmail.com"},
        {"key": "username", "value": "erickmhq"},
    ],
}


class PasswdTestCase(APITestCase):
    def setUp(self):
        self.master_key = "123456"
        self.customer = Customer(
            username="test_email@server.com",
            email="test_email@server.com",
        )
        self.customer.set_password("t35T_p455W0rD")
        self.customer.save(master_key=self.master_key)
        self.api_key = self.customer.apikey_set.filter(active=True).first()
        self.access_token = self.api_key.active_access_token

    def perform_api_auth_request_token(self):
        request_data = {"api_key": self.api_key.value, "secret_key": self.customer.secret_key}
        return self.client.post(
            path=reverse("api_auth_request_token"),
            data=request_data,
        )

    def perform_api_auth_refresh_token(self, old_access_token):
        request_data = {
            "api_key": self.api_key.value,
            "secret_key": self.customer.secret_key,
            "access_token": old_access_token,
        }
        return self.client.post(
            path=reverse("api_auth_refresh_token"),
            data=request_data,
        )

    def perform_api_get_passwd(self, passwd_uuid):
        request_data = {
            "api_key": self.api_key.value,
            "master_key": self.master_key,
            "passwd_uuid": passwd_uuid,
        }
        response = self.client.post(
            path=reverse("api_get_passwd"),
            data=request_data,
            HTTP_AUTHORIZATION=f"Bearer {self.access_token.value}",
        )
        return response

    def perform_api_add_passwd(self):
        request_body = {
            "api_key": self.api_key.value,
            "master_key": self.master_key,
            "passwd": test_passwd,
        }
        response = self.client.post(
            path=reverse("api_add_passwd"),
            data=request_body,
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {self.access_token.value}",
        )
        return response

    def test_customer_api_key_format(self):
        self.assertTrue(len(self.api_key.value) == 44)

    def test_api_auth_request_token(self):
        response = self.perform_api_auth_request_token()
        access_token = json.loads(response.content)["access_token"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(access_token), 172)

    def test_api_auth_refresh_token(self):
        request_response = self.perform_api_auth_request_token()
        old_access_token = json.loads(request_response.content)["access_token"]
        refresh_response = self.perform_api_auth_refresh_token(old_access_token)
        new_access_token = json.loads(refresh_response.content)["access_token"]
        self.assertEqual(refresh_response.status_code, 200)
        self.assertEqual(len(new_access_token), 172)
        self.assertNotEqual(old_access_token, new_access_token)

    def test_api_add_passwd(self):
        response = self.perform_api_add_passwd()
        dict_response = json.loads(response.content)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(dict_response["success"])

        passwd_data = dict_response["passwd_data"]
        passwd_uuid = passwd_data["uuid"]
        identifiers_uuids = []
        for identifier in passwd_data["identifiers"]:
            identifiers_uuids.append(identifier["uuid"])

        expected_passwd_data = {
            "uuid": passwd_uuid,
            "name": "Passtore",
            "container": {},
            "url": "https://www.passtore.com",
            "website": "www.passtore.com",
            "value": "Ipvce880920",
            "notes": "This is a note for this password.",
            "identifiers": [
                {
                    "uuid": identifiers_uuids[0],
                    "key": "email",
                    "value": "erickmhq@gmail.com",
                },
                {
                    "uuid": identifiers_uuids[1],
                    "key": "username",
                    "value": "erickmhq",
                },
            ],
        }
        self.assertEqual(expected_passwd_data, passwd_data)
        self.assertIsNotNone(Passwd.objects.get(uuid=passwd_uuid))

    def test_api_get_passwd(self):
        response = self.perform_api_add_passwd()
        dict_response = json.loads(response.content)
        passwd_uuid = dict_response["passwd_data"]["uuid"]
        get_passwd_response = self.perform_api_get_passwd(passwd_uuid)
        self.assertEqual(get_passwd_response.status_code, 200)
