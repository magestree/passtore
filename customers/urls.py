
from django.urls import path
from customers import views


urlpatterns = [
    path('login/', views.customers_login, name='customers_login'),
    path('logout/', views.customers_logout, name='customers_logout'),
    path('register/', views.customers_register, name='customers_register'),
    path('profile/', views.customers_profile, name='customers_profile'),
    path('ips-management/', views.customers_ips_management, name='customers_ips_management'),
    path('forgot-password/', views.customers_forgot_passwd, name='customers_forgot_passwd'),
    path('set-password/', views.customers_set_password, name='customers_set_password'),
]