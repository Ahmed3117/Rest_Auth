from asyncio.windows_events import NULL
from email.policy import default
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.db import models
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from .manager import CustomUserManager

# Create your models here.
# class Login(models.Model):
#     user = models.ForeignKey("CustomUser", on_delete=models.CASCADE)
#     timestamp = models.DateTimeField(default=timezone.now)
#     ip_address = models.CharField(max_length=100)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_("email address"), unique=True)
    name = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    gender = models.CharField(max_length=10, choices=(('M', 'Male'), ('F', 'Female')), blank=True)
    language = models.CharField(max_length=50, blank=True)
    image_profile = models.ImageField(upload_to='profile_images', blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS =  ["name", "gender", "language", "phone_number","image_profile"]
   
    objects = CustomUserManager()

    def __str__(self):
        return self.email
 
 
'''''   
class OneTimePasswordToken(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)

    def is_expired(self):
        return self.created_at + timezone.timedelta(hours=1) < timezone.now()
'''''        
    


