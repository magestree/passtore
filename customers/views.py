import datetime
import hmac

from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
# from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from ipware import get_client_ip

from customers.models import Customer, RecoverCode, AllowedIP
from passtore.settings import LOGIN_URL
from store.models import Passwd
from support.emails import send_email
from support.globals import SUCCESS_MESSAGE, DANGER_MESSAGE
import logging


def get_session_customer(request):
    try:
        master_key = request.session.get('master_key')
        customer = request.user.customer
        if not customer.validate_master_key(master_key):
            return None, None
        return customer, master_key
    except Exception as e:
        logging.error(e)
        return None, None


def check_session_message(request):
    """returns (if exists) any message and its class style stored in current request session."""
    if 'message' in request.session and 'class_alert' in request.session:
        message, class_alert = request.session.get('message'), request.session.get('class_alert')
        del request.session['message']
        del request.session['class_alert']
        return message, class_alert
    else:
        return None, None


@login_required(login_url=LOGIN_URL)
def customers_profile(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect('customers_logout')

    message, class_alert = check_session_message(request)
    if request.method == 'POST':
        request_post = request.POST
        if 'update_customer_data' in request_post:
            customer.email = request_post.get('email')
            customer.save()

        elif 'update_password' in request_post:
            current_password = request_post.get('current_password')
            new_password = request_post.get('new_password')
            if new_password and authenticate(username=customer.username, password=current_password):
                customer.set_password(new_password)
                customer.save()
                login(request, customer)

        if 'update_master_key' in request_post:
            new_master_key = request_post.get('master_key')
            if Passwd.validate_master_key_format(new_master_key):
                customer.update_master_key(master_key, new_master_key)
                request.session['master_key'] = new_master_key

    context = {
        "message": message,
        "class_alert": class_alert,
        'email': customer.email,
    }
    return render(request, 'customers/customers_profile.html', context)


@login_required(login_url=LOGIN_URL)
def customers_ips_management(request):
    # Authentication
    customer, master_key = get_session_customer(request)
    if not customer or not master_key:
        return redirect("customers_logout")

    message, class_alert = check_session_message(request)
    if request.method == "POST":
        request_post = request.POST
        if "add_allowed_ip" in request_post:
            name = request_post.get("name")
            ip_range = request_post.get("ip_range")
            AllowedIP.objects.create(
                customer=customer,
                name=name,
                ip_range=ip_range,
            )
            message = "Allowed IP has been correctly created"
            class_alert = SUCCESS_MESSAGE

    allowed_ips = customer.allowedip_set.all()

    context = {
        "message": message,
        "class_alert": class_alert,
        "customer": customer,
        "allowed_ips": allowed_ips,
    }
    return render(request, 'customers/customers_ips_management.html', context)


@login_required(login_url=LOGIN_URL)
def customers_logout(request):
    logout(request)
    return redirect('customers_login')


@csrf_exempt
def customers_login(request):
    if request.user.is_authenticated:
        return redirect('store_view_passwds')
    message, class_alert = check_session_message(request)
    if request.method == 'POST':
        request_post = request.POST
        client_ip, is_routable = get_client_ip(request)
        email = request_post.get('email')
        password = request_post.get('password')
        master_key = request_post.get('master_key')
        customer = Customer.objects.filter(email=email).first()
        if customer:
            if authenticate(username=customer.username, password=password):
                if customer.validate_master_key(master_key=master_key):
                    if customer.validate_ip(client_ip):
                        login(request, customer)
                        request.session['master_key'] = master_key if master_key else redirect('customers_logout')
                        # Verifying if there is next instruction in request GET
                        if 'next' not in request.GET:
                            return redirect('store_view_passwds')
                        else:
                            return redirect(request.GET.get('next'))
                    else:
                        message = "Access denied from current IP"
                        class_alert = DANGER_MESSAGE
                else:
                    message = 'Wrong Master Key'
                    class_alert = DANGER_MESSAGE
            else:
                message = 'Wrong email or password'
                class_alert = DANGER_MESSAGE
        else:
            message = 'Wrong email or password'
            class_alert = DANGER_MESSAGE
    context = {
        "message": message,
        "class_alert": class_alert,
    }
    return render(request, 'customers/customers_login.html', context)


def customers_register(request):
    if request.user.is_authenticated:
        return redirect('store_view_passwds')
    message, class_alert = check_session_message(request)
    email = None
    if request.method == 'POST':
        request_post = request.POST
        email = request_post.get('email')
        password = request_post.get('password')
        master_key = request_post.get('master_key')
        if Passwd.validate_master_key_format(master_key):
            if not Customer.objects.filter(email=email):
                customer = Customer(
                    email=email,
                    username=email,
                )
                customer.set_password(password)
                customer.save(master_key=master_key)
                request.session["message"] = "Ha creado su cuenta correctamente."
                request.session["class_alert"] = SUCCESS_MESSAGE
                return redirect('customers_login')
    context = {
        "message": message,
        "class_alert": class_alert,
        'email': email,
    }
    return render(request, 'customers/customers_register.html', context)


def customers_forgot_passwd(request):
    if request.user.is_authenticated:
        return redirect("store_view_passwds")
    message, class_alert = check_session_message(request)
    if request.method == 'POST':
        request_post = request.POST
        email = request_post.get('email')
        if Customer.objects.filter(email=email).exists():
            recovery_code = RecoverCode.objects.create(email=email)
            send_email(
                app="customers",
                template="forgot_password",
                subject="Recovery password code",
                context={
                    "title": "Your recovery code",
                    "recovery_code":  recovery_code.code,
                },
                target=email,
            )
        request.session['message'] = "We have sent a 6-character code to the email address you provided " \
                                     "(if it exists in our records). " \
                                     "Please enter that code below, and the value of your new password."
        request.session["class_alert"] = SUCCESS_MESSAGE
        request.session["email"] = email
        return redirect('customers_set_password')

    context = {
        "message": message,
        "class_alert": class_alert,
    }
    return render(request, 'customers/customers_forgot_password.html', context)


def customers_set_password(request):
    if request.user.is_authenticated:
        return redirect("store_view_passwds")
    message, class_alert = check_session_message(request)
    if request.method == 'POST':
        request_post = request.POST
        recovery_code = request_post.get('recovery_code')
        email = request.session.get("email")
        if email:
            del request.session["email"]
            if RecoverCode.objects.filter(
                code=recovery_code,
                expire__gte=datetime.datetime.utcnow(),
                email=email
            ).exists():
                password = request_post.get("password")
                password_2 = request_post.get("password_2")
                if hmac.compare_digest(password, password_2):
                    customer = Customer.objects.get(email=email)
                    customer.set_password(password)
                    customer.save()
                    request.session["message"] = "Su contraseña se ha actualizado correctamente. Inicie sesión nuevamente"
                    request.session["class_alert"] = SUCCESS_MESSAGE
                    return redirect("customers_login")
                else:
                    message = "Las contraseñas no coinciden"
                    class_alert = DANGER_MESSAGE
            else:
                message = "El código de recuperación es incorrecto o ha expirado"
                class_alert = DANGER_MESSAGE
        else:
            request.session["message"] = "Se ha producido un error al identificar el usuario, por favor inténtelo de nuevo"
            request.session["class_alert"] = DANGER_MESSAGE
            return redirect("customers_forgot_passwd")

    context = {
        "message": message,
        "class_alert": class_alert,
    }
    return render(request, 'customers/customers_set_passwd.html', context)