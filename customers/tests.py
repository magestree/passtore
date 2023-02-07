import random

from django.test import Client, TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from customers.models import Customer, AllowedIP


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

    @staticmethod
    def generate_ip():
        ip_list = []
        for i in range(4):
            ip_list.append(str(random.randint(1, 255)))
        return ".".join(ip_list)

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

    def test_allowed_ip(self):
        client_ip = self.generate_ip()
        last_oct = int(client_ip.split(".")[-1])
        client = Client(enforce_csrf_checks=False, REMOTE_ADDR=client_ip)
        auth_data = self.generate_auth_data()
        # register new Customer
        path = reverse("customers_register")
        client.post(path, auth_data)
        customer = Customer.objects.get(email=auth_data["email"])
        # create allowed_ip
        name = get_random_string(length=12)
        ip_range = f"{client_ip}-{min(last_oct + 10, 255)}"
        allowed_ip = AllowedIP.objects.create(
            customer=customer,
            name=name,
            ip_range=ip_range
        )
        self.assertTrue(customer.allowedip_set.filter(name=name, ip_range=ip_range).exists())
        # get customer's allowed_ips
        allowed_ips = customer.get_allowed_ips()
        self.assertEqual(type(allowed_ips), list)
        self.assertEqual(len(allowed_ips), min(last_oct + 10, 255) - last_oct + 1)

        # login allowed with correct IP
        login_path = reverse("customers_login")
        response = client.post(login_path, auth_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("store_view_passwds"))
        # login denied with incorrect IP
        allowed_ip.ip_range = get_random_string(length=12)
        allowed_ip.save()
        logout_path = reverse("customers_logout")
        client.get(logout_path)
        response = client.post(login_path, auth_data)
        self.assertEqual(response.status_code, 200)
        # login allowed without AllowedIP
        allowed_ip.delete()
        response = client.post(login_path, auth_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("store_view_passwds"))

