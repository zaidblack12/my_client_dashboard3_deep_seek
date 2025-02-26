from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import OTPRequestForm
import requests
import logging
from django_ratelimit.decorators import ratelimit

from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from .utils import encrypt_data, decrypt_data
from .forms import RegistrationForm
from .utils import send_verification_email
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm

logger = logging.getLogger(__name__)

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            send_verification_email(user)  # Send verification email
            return redirect('registration_success')
    else:
        form = RegistrationForm()
    return render(request, 'otp_app/register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'otp_app/login.html', {'form': form})


@login_required
def dashboard(request):
    return render(request, 'otp_app/dashboard.html')

@ratelimit(key='user', rate='5/m')
@login_required
def request_otp(request):
    if request.method == 'POST':
        form = OTPRequestForm(request.POST)
        if form.is_valid():
            date = form.cleaned_data['date']
            mobile_number = form.cleaned_data['mobile_number']

            # Fetch OTP records from the backend
            otp_records = fetch_otp_records_from_backend(date, mobile_number)

            # Encrypt the OTP records
            encrypted_records = encrypt_data(otp_records)

            # Send the encrypted records via email
            send_email(request.user.email, encrypted_records)

            return render(request, 'otp_app/request_otp.html', {'form': form, 'status': 'Email sent successfully'})
        
def get_jwt_token(username):
    # Mock function to get a JWT token for the user
    # Replace this with actual logic to get a token (e.g., call FastAPI's /token endpoint)
    url = "http://localhost:8001/token"
    data = {"username": username, "password": "password1"}  # Replace with actual user credentials
    response = requests.post(url, json=data)
    return response.json().get('access_token')

def request_otp_from_backend(date, mobile_number, token):
    url = "http://localhost:8001/request-otp/"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"date": date, "mobile_number": mobile_number}
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        otp_records = response.json().get('otp_records')

        # Encrypt the OTP records
        encrypted_records = encrypt_data(otp_records)

        # Send the encrypted records via email
        user_email = request.user.email
        send_otp_email(user_email, encrypted_records)  # Use send_ses_email for AWS SES

        return {"status": "Email sent successfully"}
    except requests.exceptions.RequestException as e:
        return {"status": f"Error: {str(e)}"}




def verify_email(request, uidb64, token):
    User = get_user_model()
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.client.email_verified = True
        user.client.save()
        return redirect('dashboard')
    else:
        return redirect('invalid_verification')
    


def send_otp_email(email, encrypted_data):
    subject = "Your OTP Records"
    message = render_to_string('otp_app/email_template.html', {'encrypted_data': encrypted_data})
    email_message = EmailMessage(subject, message, 'from@example.com', [email])
    email_message.content_subtype = 'html'
    email_message.send()

def some_view(request):
    data = "Sensitive data"
    encrypted_data = encrypt_data(data)
    decrypted_data = decrypt_data(encrypted_data)