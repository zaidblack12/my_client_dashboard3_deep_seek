from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import OTPRequestForm
import requests
import logging

logger = logging.getLogger(__name__)

@login_required
def dashboard(request):
    return render(request, 'otp_app/dashboard.html')

@login_required
def request_otp(request):
    if request.method == 'POST':
        form = OTPRequestForm(request.POST)
        if form.is_valid():
            date = form.cleaned_data['date']
            mobile_number = form.cleaned_data['mobile_number']

            # Get the JWT token for the logged-in user
            token = get_jwt_token(request.user.username)

            # Call the FastAPI backend
            response = request_otp_from_backend(date, mobile_number, token)

            # Display the response status
            return render(request, 'otp_app/request_otp.html', {'form': form, 'status': response.get('status')})
    else:
        form = OTPRequestForm()
    return render(request, 'otp_app/request_otp.html', {'form': form})

def get_jwt_token(username):
    # Mock function to get a JWT token for the user
    # Replace this with actual logic to get a token (e.g., call FastAPI's /token endpoint)
    url = "http://localhost:8001/token"
    data = {"username": username, "password": "password1"}  # Replace with actual user credentials
    response = requests.post(url, json=data)
    return response.json().get('access_token')

def request_otp_from_backend(date, mobile_number, token):
    url = "http://localhost:8000/request-otp/"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"date": date, "mobile_number": mobile_number}
    try:
        logger.info(f"Sending OTP request for {mobile_number} on {date}")
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        logger.info(f"OTP request successful: {response.json()}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"OTP request failed: {str(e)}")
        return {"status": f"Error: {str(e)}"}