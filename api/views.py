import json

from django.contrib.auth.decorators import login_required
from django.core import serializers
from django.db.models import Q
from django.forms.models import model_to_dict
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_405_METHOD_NOT_ALLOWED,
)

from passtore.settings import LOGIN_URL
from store.models import Passwd, Identifier, FernetKey
from support.functions import encrypt_string, decrypt_string
from customers.models import Customer, ApiKey, AccessToken


def get_authorized_customer(request_headers, request_body):
    authorization_header = request_headers.get("Authorization", "")
    if authorization_header:
        api_key_value = request_body.get("api_key")
        api_key = ApiKey.objects.filter(value=api_key_value, active=True).first()
        master_key = request_body.get("master_key")
        if api_key and master_key:
            access_token_value = authorization_header.split("Bearer ")[1]
            access_token = api_key.accesstoken_set.filter(value=access_token_value, active=True).first()
            if access_token:
                master_key_validated = api_key.customer.validate_master_key(master_key)
                if master_key_validated:
                    return api_key.customer
    return None


@csrf_exempt
def api_auth_request_token(request):
    if request.method == "POST":
        """Example of json to request access_token:
        {
            "api_key": "*********************",
            "secret_key": "*******************************",
        }
        Example of response with access_token:
        {
            "success": True,
            "access_token": "************************************"
            # TODO: "expiration": "9879655764",
        }
        """
        success = False
        access_token = ""
        message = "Wrong credentials."
        status_code = HTTP_403_FORBIDDEN
        request_post = request.POST
        api_key_value = request_post["api_key"]
        secret_key = request_post["secret_key"]
        api_key = ApiKey.objects.filter(value=api_key_value, active=True).first()
        if api_key and api_key.customer.secret_key == secret_key:
            success = True
            access_token = AccessToken.objects.get_or_create(api_key=api_key)[0].value
            message = "Access token successfully granted"
            status_code = HTTP_200_OK
        response = {
            "success": success,
            "access_token": access_token,
            "message": message,
        }
        return JsonResponse(response, status=status_code)


@csrf_exempt
def api_auth_refresh_token(request):
    if request.method == "POST":
        """Example of json to refresh access_token:
        {
            "api_key": "*********************",
            "secret_key": "*******************************",
            "access_token: "************************************"
        }
        Example of response with access_token:
        {
            "success": True,
            "access_token": "************************************"
            # TODO: "expiration": "9879655764",
        }
        """
        success = False
        message = "Wrong credentials."
        status_code = HTTP_403_FORBIDDEN
        request_post = request.POST
        api_key_value = request_post["api_key"]
        secret_key = request_post["secret_key"]
        access_token = request_post["access_token"]
        api_key = ApiKey.objects.filter(value=api_key_value, active=True).first()
        if api_key and api_key.customer.secret_key == secret_key:
            current_access_token = api_key.accesstoken_set.filter(value=access_token).first()
            if current_access_token:
                success = True
                access_token = AccessToken.objects.create(api_key=api_key).value
                message = "Access token successfully generated"
                status_code = HTTP_200_OK
        response = {
            "success": success,
            "access_token": access_token,
            "message": message,
        }
        return JsonResponse(response, status=status_code)


@csrf_exempt
def api_get_passwd(request):
    """Example of request content:
    request headers => {
        "Authorization": "Bearer ***********************************************"  # access_token
    }
    request data => {
        "api_key": "**********************",
        "master_key": "<MASTER_KEY>",
        "passwd_uuid": "<PASSWD_UUID>",
    }
    """
    success = False
    passwd_data = {}
    status_code = HTTP_405_METHOD_NOT_ALLOWED  # Set status_code as Method Not Allowed
    if request.method == "POST":
        status_code = HTTP_401_UNAUTHORIZED  # Set status_code as Unauthorized
        request_post = request.POST
        request_body = {"api_key": request_post.get("api_key"), "master_key": request_post.get("master_key")}
        customer = get_authorized_customer(request_headers=request.headers, request_body=request_body)
        if customer:
            passwd = customer.passwd_set.filter(uuid=request_post.get("passwd_uuid"), available=True).first()
            if passwd:
                passwd_value = decrypt_string(passwd.value, request_body["master_key"])
                if passwd_value:
                    identifiers = []
                    for identifier in passwd.identifier_set.all():
                        identifiers.append(
                            {
                                "uuid": identifier.uuid,
                                "key": identifier.key,
                                "value": identifier.value,
                            }
                        )
                    container = (
                        {"uuid": passwd.container.uuid, "name": passwd.container.name} if passwd.container else {}
                    )
                    passwd_data = {
                        "uuid": passwd.uuid,
                        "name": passwd.name,
                        "container": container,
                        "url": passwd.url,
                        "website": passwd.website,
                        "value": passwd_value,
                        "notes": passwd.notes,
                        "identifiers": identifiers,
                    }
                    success = True
                    status_code = HTTP_200_OK

    response = {
        "success": success,
        "passwd_data": passwd_data,
    }
    return JsonResponse(response, status=status_code)


@csrf_exempt
def api_get_passwds_from_url(request):
    """Example of request content:
    request headers => {
        "Authorization": "Bearer ***********************************************"  # access_token
    }
    request body => {
        "api_key": "**********************",
        "master_key": "<MASTER_KEY>",
        "url": "<URL>",
    }
    """
    success = False
    passwd_data = {}
    status_code = HTTP_405_METHOD_NOT_ALLOWED  # Set status_code as Method Not Allowed
    if request.method == "POST":
        status_code = HTTP_401_UNAUTHORIZED
        passwds_data = []
        request_body = json.loads(request.body)
        customer = get_authorized_customer(request_headers=request.headers, request_body=request_body)
        if customer:
            url = request_body.get("url")
            if url:
                passwds = Passwd.get_passwds_from_url(url)

                # TODO
                container_uuid = passwd_data.get("container")
                container = customer.container_set.filter(uuid=container_uuid).first()
                passwd = Passwd(
                    customer=customer,
                    name=passwd_data.get("name"),
                    container=container,
                    url=passwd_data.get("url"),
                    value=passwd_data.get("value"),
                    notes=passwd_data.get("notes"),
                )
                passwd.save(master_key=request.session["master_key"])
                for identifier in passwd_data.get("identifiers"):
                    key = identifier.get("key")
                    value = identifier.get("value")
                    if key and value:
                        Identifier.objects.create(
                            passwd=passwd,
                            key=key,
                            value=value,
                        )
                success = True
                status_code = HTTP_201_CREATED
                identifiers = []
                for identifier in passwd.identifier_set.all():
                    identifiers.append(
                        {
                            "uuid": identifier.uuid,
                            "key": identifier.key,
                            "value": identifier.value,
                        }
                    )
                container = (
                    {"uuid": passwd.container.uuid, "name": passwd.container.name} if passwd.container else {}
                )
                passwd_data = {
                    "uuid": passwd.uuid,
                    "name": passwd.name,
                    "container": container,
                    "url": passwd.url,
                    "website": passwd.website,
                    "value": decrypt_string(passwd.value, request_body.get("master_key")),
                    "notes": passwd.notes,
                    "identifiers": identifiers,
                }

        response = {
            "success": success,
            "passwd_data": passwd_data,
        }
        return JsonResponse(response, status=status_code)


@csrf_exempt
def api_add_passwd(request):
    """Example of request content:
    request headers => {
        "Authorization": "Bearer ***********************************************"  # access_token
    }
    request body => {
        "api_key": "**********************",
        "master_key": "<MASTER_KEY>"
        "passwd": {
            "name": "<PASSWD_NAME>",  # Optional
            "container": "<CONTAINER_UUID>",  # Optional
            "url": "<PASSWD_URL>",
            "value": "<PASSWD_VALUE>",
            "notes": "<PASSWD_NOTES>"  # Optional
            "identifiers": [
                {"key": "<IDENTIFIER_1_KEY>", "value": "<IDENTIFIER_1_VALUE>"},
                {"key": "<IDENTIFIER_2_KEY>", "value": "<IDENTIFIER_2_VALUE>"},
                ...
                {"key": "<IDENTIFIER_n_KEY>", "value": "<IDENTIFIER_n_VALUE>"},
            ]
        }
    }
    """
    if request.method == "POST":
        success = False
        status_code = HTTP_401_UNAUTHORIZED
        passwd_data = {}
        request_body = json.loads(request.body)
        message = ""
        authorization_header = request.headers.get("Authorization", "")
        if authorization_header:
            api_key_value = request_body.get("api_key")
            api_key = ApiKey.objects.filter(value=api_key_value, active=True).first()
            if api_key:
                master_key = request_body.get("master_key")
                if master_key:
                    access_token_value = authorization_header.split("Bearer ")[1]
                    access_token = api_key.accesstoken_set.filter(value=access_token_value, active=True).first()
                    if access_token:
                        master_key_is_correct = api_key.customer.validate_master_key(master_key)
                        if master_key_is_correct:
                            passwd_data = request_body.get("passwd")
                            if passwd_data:
                                container_uuid = passwd_data.get("container")
                                container = api_key.customer.container_set.filter(uuid=container_uuid).first()
                                passwd = Passwd(
                                    customer=api_key.customer,
                                    name=passwd_data.get("name"),
                                    container=container,
                                    url=passwd_data.get("url"),
                                    value=passwd_data.get("value"),
                                    notes=passwd_data.get("notes"),
                                )
                                passwd.save(master_key=request_body.get("master_key"))
                                for identifier in passwd_data.get("identifiers"):
                                    key = identifier.get("key")
                                    value = identifier.get("value")
                                    if key and value:
                                        Identifier.objects.create(
                                            passwd=passwd,
                                            key=key,
                                            value=value,
                                        )
                                success = True
                                status_code = HTTP_201_CREATED
                                identifiers = []
                                for identifier in passwd.identifier_set.all():
                                    identifiers.append(
                                        {
                                            "uuid": identifier.uuid,
                                            "key": identifier.key,
                                            "value": identifier.value,
                                        }
                                    )
                                container = (
                                    {"uuid": passwd.container.uuid, "name": passwd.container.name} if passwd.container else {}
                                )
                                passwd_data = {
                                    "uuid": passwd.uuid,
                                    "name": passwd.name,
                                    "container": container,
                                    "url": passwd.url,
                                    "website": passwd.website,
                                    "value": decrypt_string(passwd.value, request_body.get("master_key")),
                                    "notes": passwd.notes,
                                    "identifiers": identifiers,
                                }
                            else:
                                message = "passwd_data not found"
                        else:
                            message = "unable to validate customer with provided master_key"
                    else:
                        message = "Missing access_token"
                else:
                    message = "Missing master_key"
            else:
                message = "Missing api_key"
        else:
            message = "Missing authorization_header"

        response = {
            "success": success,
            "passwd_data": passwd_data,
            "message": message,
        }
        return JsonResponse(response, status=status_code)
