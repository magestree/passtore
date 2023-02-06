from django.urls import path
from store import views


urlpatterns = [
    path('', views.store_view_passwds, name='store_view_passwds'),
    path('view-shared-passwords/', views.store_view_shared_passwds, name='store_view_shared_passwds'),
    path('view-containers/', views.store_view_containers, name='store_view_containers'),
    path('add-password/', views.store_add_passwd, name='store_add_passwd'),
    path('update-password/<str:passwd_uuid>/', views.store_update_passwd, name='store_update_passwd'),
    path('delete-password/<str:passwd_uuid>/', views.store_delete_passwd, name='store_delete_passwd'),
    path('copy-shared-password/<str:shared_passwd_uuid>/', views.store_copy_shared_passwd, name='store_copy_shared_passwd'),
    path('delete-shared-password/<str:shared_passwd_uuid>/', views.store_delete_shared_passwd, name='store_delete_shared_passwd'),
    path('delete-sharing-password/<str:sharing_passwd_uuid>/', views.store_delete_sharing_passwd, name='store_delete_sharing_passwd'),
    path('reveal-password/', views.store_reveal_passwd, name='store_reveal_passwd'),
    path('reveal-shared-password/', views.store_reveal_shared_passwd, name='store_reveal_shared_passwd'),
    path('update-container/<str:container_uuid>/', views.store_update_container, name='store_update_container'),
    path('delete-container/<str:container_uuid>/', views.store_delete_container, name='store_delete_container'),
    path('add-container/', views.store_add_container, name='store_add_container'),
]
