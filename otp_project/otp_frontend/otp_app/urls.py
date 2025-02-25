from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('request-otp/', views.request_otp, name='request_otp'),
]