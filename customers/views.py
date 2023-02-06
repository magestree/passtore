import re

from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from customers.models import Customer, RecoverCode
from passtore.settings import LOGIN_URL
from store.models import FernetKey, Passwd


def get_session_customer(request):
    master_key = request.session.get('master_key')
    customer = request.user.customer
    if not customer.validate_master_key(master_key):
        return redirect('customers_logout')
    return customer, master_key


@login_required(login_url=LOGIN_URL)
def customers_profile(request):
    # Authentication
    customer, master_key = get_session_customer(request)

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
        'email': customer.email,
    }
    return render(request, 'customers/customers_profile.html', context)


@login_required(login_url=LOGIN_URL)
def customers_logout(request):
    logout(request)
    return redirect('customers_login')


def customers_login(request):
    if request.user.is_authenticated:
        return redirect('store_view_passwds')
    email = ''
    master_key = ''
    if request.method == 'POST':
        request_post = request.POST
        email = request_post.get('email')
        password = request_post.get('password')
        master_key = request_post.get('master_key')
        customer = Customer.objects.filter(email=email).first()
        if customer:
            if authenticate(username=customer.username, password=password):
                if customer.validate_master_key(master_key=master_key):
                    login(request, customer)
                    request.session['master_key'] = master_key if master_key else redirect('customers_logout')
                    # Verifying if there is next instruction in request GET
                    if 'next' not in request.GET:
                        return redirect('store_view_passwds')
                    else:
                        return redirect(request.GET.get('next'))
                else:
                    error = 'Pin de seguridad incorrecto'
            else:
                error = 'Email o contraseña incorrecto'
        else:
            error = 'Email o contraseña incorrecto'
        request.session['error'] = error
    context = {
        'email': email,
        'master_key': master_key,
    }
    return render(request, 'customers/customers_login.html', context)


def customers_register(request):
    if request.user.is_authenticated:
        return redirect('store_view_passwds')
    email = ''
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
                return redirect('customers_login')
    context = {
        'email': email,
    }
    return render(request, 'customers/customers_register.html', context)


def customers_forgot_passwd(request):
    email = ''
    if request.method == 'POST':
        request_post = request.POST
        email = request_post.get('email')
        RecoverCode.objects.create(email=email)
        request.session['message'] = str(_('We have sent a 6-character code to the email address you provided '
                                           '(if it exists in our records). Please enter that code below, '
                                           'and the value of your new password.'))
        return redirect('customers_validate_code_recover')
    context = {
        'email': email,
    }
    return render(request, 'customers/customers_forgot_passwd.html', context)


def customers_validate_code_recover(request):
    context = {
        'code': '',
    }
    if request.method == 'POST':
        request_post = request.POST
        code = request_post.get('code')
        current_time = now()
        recover_code = RecoverCode.objects.filter(code__iexact=code, expire__gte=current_time)
        if not recover_code.exists():
            request.session['error'] = str(_('Codigo invalido o expirado'))
        else:
            recover_code = recover_code.first()
            try:
                request.session['user_id'] = User.objects.get(email=recover_code.email).id
                return render(request, 'customers/customers_set_passwd.html', context)
            except User.DoesNotExist:
                request.session['error'] = str(_('Codigo invalido o expirado'))
    return render(request, 'customers/customers_validate_code_recover.html', context)


def customers_set_password_recover(request):
    context = {}
    if request.method == 'POST':
        request_post = request.POST
        user_id = request.session['user_id']
        password = request_post.get('password')
        password2 = request_post.get('password2')
        if password != password2:
            request.session['error'] = str(_('Las contrasennas deben coincidir'))
        else:
            u = User.objects.get(id=user_id)
            u.set_password(password)
            u.save()
            del request.session['user_id']
            return redirect('customers_login')

    return render(request, 'customers/customers_set_passwd.html', context)