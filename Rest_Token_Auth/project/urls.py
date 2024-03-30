
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
# from users.api import CustomUserViewSet, LoginViewSet, CustomUserCreationViewSet, UserViewSet

# router = DefaultRouter()
# router.register(r'users', CustomUserViewSet)
# router.register(r'logins', LoginViewSet, basename='loginjwt')
# router.register(r'user-profile', CustomUserCreationViewSet, basename='user-profile')
# router.register(r'users', UserViewSet, basename='users')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('users.urls')),
    
    # path('api/', include(router.urls)),  # Include the DRF viewsets URLs under the /api/ path
    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

