from django.test import Client, TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from customers.models import Customer


class CustomerAuthTestCase(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=False)

    @staticmethod
    def generate_auth_data():
        return {
            "email": f"{get_random_string(length=12)}@{get_random_string(length=12)}.com",
            "password": get_random_string(length=12),
            "master_key": get_random_string(length=6, allowed_chars="0123456789"),
        }

    def test_register(self):
        auth_data = self.generate_auth_data()
        path = reverse("customers_register")
        response = self.client.post(path, auth_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("customers_login"))
        self.assertTrue(Customer.objects.filter(email=auth_data["email"]).exists())

    def test_login(self):
        auth_data = self.generate_auth_data()
        # perform register
        register_path = reverse("customers_register")
        self.client.post(register_path, auth_data)
        # test login
        login_path = reverse("customers_login")
        response = self.client.post(login_path, auth_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("store_view_passwds"))