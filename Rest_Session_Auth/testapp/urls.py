from django.urls import path
from . import views

urlpatterns = [
	path('testpage', views.testpage, name='testpage'),
	
]