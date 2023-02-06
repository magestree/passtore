from django.urls import path
from customers import views


urlpatterns = [
    path('login/', views.customers_login, name='customers_login'),
    path('logout/', views.customers_logout, name='customers_logout'),
    path('register/', views.customers_register, name='customers_register'),
    path('profile/', views.customers_profile, name='customers_profile'),
    path('forgot_passwd/', views.customers_forgot_passwd, name='customers_forgot_passwd'),
    path('validate_code/', views.customers_validate_code_recover, name='customers_validate_code_recover'),
    path('set_password_recover/', views.customers_set_password_recover, name='customers_set_password_recover'),
]
