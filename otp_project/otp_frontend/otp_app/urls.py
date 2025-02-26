from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),  # Registration URL
    path('login/', views.login_view, name='login'), 
    path('dashboard/', views.dashboard, name='dashboard'),
    path('request-otp/', views.request_otp, name='request_otp'),
    path('verify-email/<uidb64>/<token>/', views.verify_email, name='verify_email'),
]