import json

from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt
import requests

from customers.views import get_session_customer, check_session_message
from passtore.settings import LOGIN_URL
from store.models import Passwd, SharedPasswd, Identifier, Container, FernetKey
from support.functions import encrypt_string, decrypt_string, reencrypt_string
from support.globals import SUCCESS_MESSAGE, DANGER_MESSAGE


def build_url(request, url_name):
    host = f'{request.scheme}://{request.get_host()}'
    tail = reverse_lazy(url_name)
    api_url = f'{host}{tail}'
    return api_url


def get_pagination_dict(request, iterable):
    # start: Pagination
    paginator = Paginator(iterable, 50)
    page_number = request.GET.get('page') or 1
    if not isinstance(page_number, int) and not page_number.isdigit():
        page_number = 1
    if int(page_number) < 1:
        page_number = 1
    elif int(page_number) > paginator.num_pages:
        page_number = paginator.num_pages
    page_obj = paginator.get_page(page_number)

    def filter_pages(page):
        return 0 < page <= paginator.num_pages
    pages = list(filter(filter_pages, range(int(page_number) - 4, int(page_number) + 5)))
    # end: Pagination
    return {
        'paginator': paginator,
        'page_obj': page_obj,
        'pages': pages,
    }


def get_identifiers_from_request_post(request_post):
    identifiers = []
    for post_element_name, identifier_key in request_post.items():
        if post_element_name.startswith("identifier_key_"):
            order_row = post_element_name.split("_")[-1]
            identifier_value = request_post[f"identifier_value_{order_row}"]
            identifiers.append({"key": identifier_key, "value": identifier_value})
    return identifiers


@csrf_exempt
def store_reveal_passwd(request):
    if request.is_ajax and request.method == "POST":
        request_post = request.POST
        uuid = request_post["uuid"]
        master_key = request_post["master_key"]
        passwd = Passwd.objects.filter(uuid=uuid, customer=request.user).first()
        if passwd:
            return_value = decrypt_string(passwd.value, master_key)
            return JsonResponse({"value": return_value}, status=200)
    return JsonResponse({"error": ""}, status=400)


@csrf_exempt
def store_reveal_shared_passwd(request):
    if request.is_ajax and request.method == "POST":
        request_post = request.POST
        uuid = request_post["uuid"]
        master_key = request_post["master_key"]
        shared_passwd = SharedPasswd.objects.filter(uuid=uuid, customer_email=request.user.email, accepted=True).first()
        if shared_passwd:
            return_value = decrypt_string(shared_passwd.shared_value, master_key)
            return JsonResponse({"value": return_value}, status=200)
    return JsonResponse({"error": ""}, status=400)


@login_required(login_url=LOGIN_URL)
def store_add_passwd(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    containers = customer.container_set.all()

    if request.method == "POST":
        request_post = request.POST
        # add passwd
        if "add_passwd" in request_post:
            data = {
                "api_key": customer.default_api_key.value,
                "master_key": master_key,
                "passwd": {
                    "name": request_post.get("name"),
                    "container": request_post.get("container_id"),
                    "url": request_post.get("url"),
                    "value": request_post.get("value"),
                    "notes": request_post.get("notes"),
                    "identifiers": get_identifiers_from_request_post(request_post)
                },
            }
            # Make api POST request
            headers = customer.default_api_key.active_access_token.authorization_bearer
            response = requests.post(
                url=build_url(request, 'api_add_passwd'),
                headers=headers,
                json=data,
            )
            response_dict = json.loads(response.content)
            message = response_dict["message"]
            if response.status_code == 201:
                if response_dict["success"]:
                    request.session["message"] = f"Passwd successfully created. {message}"
                    request.session["class_alert"] = SUCCESS_MESSAGE
                    return redirect("store_view_passwds")
            else:
                message = f"Error creating password: {response.status_code}. {message}"
                class_alert = DANGER_MESSAGE

        # Load passwds from .xlsx scenario
        elif "load_passwds" in request_post:
            input_file = request.FILES.get("file")
            if input_file.name.endswith(".xlsx"):
                read_passwds = Passwd.read_passwds_from_xlsx(input_file)
            elif input_file.name.endswith(".csv"):
                read_passwds = Passwd.read_passwds_from_chrome_csv(input_file)
            for read_passwd in read_passwds:
                new_passwd = Passwd(
                    customer=customer,
                    container=read_passwd.get("container"),
                    name=read_passwd.get("name"),
                    url=read_passwd.get("url"),
                    value=read_passwd.get("value"),
                    notes=read_passwd.get("notes"),
                )
                new_passwd.save(master_key=master_key)
                for identifier in read_passwd.get("identifiers"):
                    for key, value in identifier.items():
                        Identifier.objects.create(
                            passwd=new_passwd,
                            key=key,
                            value=value,
                        )
            if read_passwds:
                request.session["message"] = "Passwords successfully uploaded from document"
                request.session["class_alert"] = DANGER_MESSAGE
    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "containers": containers,
    }
    return render(request, "store/store_add_passwd.html", context)


@login_required(login_url=LOGIN_URL)
def store_view_passwds(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    containers = customer.container_set.order_by("name")
    container = None
    name = None
    url = None
    identifier = None
    passwds = customer.passwd_set.prefetch_related("identifier_set").order_by("name", "website")

    if request.method == "POST":
        request_post = request.POST
        if "filter_passwds" in request_post:
            container_id = request_post.get("container_id")
            if container_id:
                container = containers.filter(id=container_id).first()
            name = request_post.get("name")
            if name:
                passwds = passwds.filter(name__icontains=name)
            url = request_post.get("url")
            if url:
                passwds = passwds.filter(url__icontains=url)
            identifier = request_post.get("identifier")
            if identifier:
                passwds = passwds.filter(identifier__value__icontains=identifier)

    # pagination
    pagination_dict = get_pagination_dict(request, passwds)
    paginator = pagination_dict['paginator']
    page_obj = pagination_dict['page_obj']
    pages = pagination_dict['pages']

    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "name": name,
        "url": url,
        "identifier": identifier,
        "passwds": passwds,
        "container": container,
        "containers": containers,
        # pagination
        'paginator': paginator,
        'page_obj': page_obj,
        'pages': pages,

        "numbers": [1, 2, 3, 4],
    }
    return render(request, "store/store_view_passwds.html", context)


@login_required(login_url=LOGIN_URL)
def store_view_shared_passwds(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    url = None
    identifier = None
    shared_passwds = (
        SharedPasswd.objects.filter(customer_email=customer.email, passwd__available=True)
        .prefetch_related("passwd__identifier_set")
        .order_by("passwd__name", "passwd__website")
    )
    sharing_passwds = (
        SharedPasswd.objects.filter(passwd__customer=customer)
        .prefetch_related("passwd__identifier_set")
        .order_by("passwd__name", "passwd__website")
    )

    if request.method == "POST":
        request_post = request.POST
        if "accept_shared_passwd" in request_post:
            shared_passwd_uuid = request_post.get("shared_passwd_uuid")
            shared_passwd = shared_passwds.filter(uuid=shared_passwd_uuid).first()
            if shared_passwd:
                tmp_master_key = request_post.get("temp_master_key")
                new_value = reencrypt_string(shared_passwd.shared_value, tmp_master_key, master_key)
                if new_value:
                    shared_passwd.shared_value = new_value
                    shared_passwd.accepted = True
                    shared_passwd.save()
    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "url": url,
        "identifier": identifier,
        "shared_passwds": shared_passwds,
        "sharing_passwds": sharing_passwds,
    }
    return render(request, "store/store_view_shared_passwds.html", context)


@login_required(login_url=LOGIN_URL)
def store_view_containers(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    name = None
    containers = customer.container_set.order_by("name")

    if request.method == "POST":
        request_post = request.POST
        if "filter_containers" in request_post:
            name = request_post.get("name")
            if name:
                containers = containers.filter(name=name)
    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "name": name,
        "containers": containers,
    }
    return render(request, "store/store_view_containers.html", context)


@login_required(login_url=LOGIN_URL)
def store_update_container(request, container_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    container = get_object_or_404(Container, customer=customer, uuid=container_uuid)

    # message
    message, class_alert = check_session_message(request)

    if request.method == "POST":
        request_post = request.POST
        if "update_container" in request_post:
            # retrieve data from request.POST
            name = request_post.get("name")
            # Update container
            container.name = name
            container.save()
            # message definition
            message = "Container successfully updated."
            class_alert = SUCCESS_MESSAGE
    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "container": container,
    }
    return render(request, "store/store_update_container.html", context)


@login_required(login_url=LOGIN_URL)
def store_update_passwd(request, passwd_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    passwd = get_object_or_404(Passwd, customer=customer, uuid=passwd_uuid)
    if not passwd.available:
        return redirect("store_view_passwds")

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    tmp_master_key = None
    template_prefix_id = "db"
    containers = customer.container_set.all()
    identifiers = passwd.identifier_set.all()

    if request.method == "POST":
        request_post = request.POST
        if "update_passwd" in request_post:
            # retrieve data from request.POST
            name = request_post.get("name") or None
            container_id = request_post.get("container_id")
            container = None if container_id == "" else containers.filter(id=container_id).first()
            url = request_post.get("url")
            raw_passwd = request_post.get("value")
            value = encrypt_string(raw_passwd, master_key)
            notes = request_post.get("notes")
            # Update passwd
            passwd.container = container
            passwd.name = name
            passwd.url = url
            passwd.value = value
            passwd.notes = notes
            passwd.save()
            # Create identifiers
            db_identifiers = []
            for post_element_name in request_post:
                if post_element_name.startswith("identifier_key_"):
                    identifier_key = request_post[post_element_name]
                    order_row = post_element_name.split("_")[-1]
                    identifier_value = request_post[f"identifier_value_{order_row}"]
                    if order_row.startswith(template_prefix_id):
                        # Update existent identifier
                        identifier_id = order_row.replace(template_prefix_id, "")
                        db_identifiers.append(identifier_id)
                        identifier = identifiers.get(id=identifier_id)
                        identifier.key = identifier_key
                        identifier.value = identifier_value
                        identifier.save()
                    elif identifier_key and identifier_value:
                        # Create new identifier
                        new_identifier = Identifier.objects.create(
                            passwd=passwd,
                            key=identifier_key,
                            value=identifier_value,
                        )
                        db_identifiers.append(new_identifier.id)
            # Delete removed old identifiers
            identifiers.exclude(id__in=db_identifiers).delete()
            # message definition
            message = "Password successfuly updated."
            class_alert = SUCCESS_MESSAGE

        elif "share_passwd" in request_post:
            customer_emails = request_post.get("customer_emails")
            emails_list = customer_emails.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            tmp_master_key = get_random_string(length=15)
            raw_passwd = decrypt_string(passwd.value, master_key)
            shared_value = encrypt_string(raw_passwd, tmp_master_key)
            for customer_email in emails_list:
                shared_passwd = SharedPasswd.objects.filter(
                    passwd=passwd,
                    customer_email=customer_email,
                ).first()
                if shared_passwd:
                    shared_passwd.shared_value = shared_value
                    shared_passwd.save()
                else:
                    SharedPasswd.objects.create(
                        passwd=passwd,
                        customer_email=customer_email,
                        shared_value=shared_value,
                    )
            if len(emails_list) > 0:
                message = "Passwd successfully shared."
                class_alert = SUCCESS_MESSAGE

    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "tmp_master_key": tmp_master_key,
        "passwd": passwd,
        "containers": containers,
        "identifiers": identifiers,
        "value": decrypt_string(passwd.value, master_key),
        "template_prefix_id": template_prefix_id,
    }
    return render(request, "store/store_update_passwd.html", context)


@login_required(login_url=LOGIN_URL)
def store_delete_passwd(request, passwd_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    passwd = get_object_or_404(Passwd, customer=customer, uuid=passwd_uuid)

    # Data processing
    passwd.delete()
    request.session["message"] = "Password successfully deleted."
    request.session["class_alert"] = SUCCESS_MESSAGE
    return redirect("store_view_passwds")


@login_required(login_url=LOGIN_URL)
def store_copy_shared_passwd(request, shared_passwd_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    shared_passwd = get_object_or_404(
        SharedPasswd, customer_email=customer.email, uuid=shared_passwd_uuid, accepted=True
    )
    # Create Passwd from SharedPasswd
    decrypted_passwd = decrypt_string(shared_passwd.shared_value, master_key)
    passwd = Passwd(
        customer=customer,
        container=None,
        name=shared_passwd.passwd.name,
        url=shared_passwd.passwd.url,
        website=shared_passwd.passwd.website,
        value=decrypted_passwd,
        notes=shared_passwd.passwd.notes,
        available=shared_passwd.passwd.available,
    )
    passwd.save(master_key=master_key)
    for shared_identifier in shared_passwd.passwd.identifier_set.all():
        Identifier.objects.create(
            passwd=passwd,
            key=shared_identifier.key,
            value=shared_identifier.value,
        )
    request.session["message"] = "Shared password was successfully saved as a new password"
    request.session["class_alert"] = SUCCESS_MESSAGE
    return redirect("store_view_shared_passwds")


@login_required(login_url=LOGIN_URL)
def store_delete_shared_passwd(request, shared_passwd_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    shared_passwd = get_object_or_404(SharedPasswd, customer_email=customer.email, uuid=shared_passwd_uuid)
    # Data processing
    shared_passwd.delete()
    request.session["message"] = "Shared password successfully deleted."
    request.session["class_alert"] = SUCCESS_MESSAGE
    return redirect("store_view_shared_passwds")


@login_required(login_url=LOGIN_URL)
def store_delete_sharing_passwd(request, sharing_passwd_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    sharing_passwd = get_object_or_404(SharedPasswd, passwd__customer=customer, uuid=sharing_passwd_uuid)
    # Data processing
    sharing_passwd.delete()
    request.session["message"] = "Shared password successfully deleted."
    request.session["class_alert"] = SUCCESS_MESSAGE
    return redirect("store_view_shared_passwds")


@login_required(login_url=LOGIN_URL)
def store_delete_container(request, container_uuid):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    container = get_object_or_404(Container, customer=customer, uuid=container_uuid)
    # Data processing
    container.delete()
    request.session["message"] = "Container successfully deleted."
    request.session["class_alert"] = SUCCESS_MESSAGE
    return redirect("store_view_containers")


@login_required(login_url=LOGIN_URL)
def store_add_container(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    # message
    message, class_alert = check_session_message(request)

    # Data definition
    container = Container(customer=customer)

    if request.method == "POST":
        request_post = request.POST
        if "add_container" in request_post:
            request_post = request.POST
            # retrieve data from request.POST
            name = request_post.get("name")
            container.name = name
            container.save()
    context = {
        # message
        "message": message,
        "class_alert": class_alert,
        # data
        "container": container,
        "customer": customer,
    }
    return render(request, "store/store_add_container.html", context)
