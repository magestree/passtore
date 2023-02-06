from django.urls import path
from api import views

urlpatterns = [
    path("auth/request-token/", views.api_auth_request_token, name="api_auth_request_token"),
    path("auth/refresh-token/", views.api_auth_refresh_token, name="api_auth_refresh_token"),
    path("add-passwd/", views.api_add_passwd, name="api_add_passwd"),
    path("get-passwd/", views.api_get_passwd, name="api_get_passwd"),
]
