from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

def send_verification_email(user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    subject = "Verify Your Email"
    message = render_to_string('otp_app/verification_email.html', {
        'user': user,
        'uid': uid,
        'token': token,
    })
    send_mail(subject, message, 'from@example.com', [user.email])

load_dotenv()
key = os.getenv('ENCRYPTION_KEY').encode()
cipher_suite = Fernet(key)

# Generate a key (store this securely in environment variables)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()