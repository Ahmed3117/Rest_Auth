from . import views
from django.contrib.auth import views as auth_views
from django.urls import path
from .api import RegisterView, LoginView, LogoutView, ChangePasswordView
urlpatterns=[
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
]
