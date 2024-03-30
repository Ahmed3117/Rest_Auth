from django.contrib import admin
from .models import CustomUser



class LoginAdmin(admin.ModelAdmin):
    list_display = ('user', 'timestamp', 'ip_address')
    search_fields = ['user__email', 'ip_address']
    list_filter = ['timestamp', 'ip_address']

# Register your models here.
admin.site.register(CustomUser)
