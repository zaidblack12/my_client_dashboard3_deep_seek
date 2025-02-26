from django import forms


class OTPRequestForm(forms.Form):
    date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    mobile_number = forms.CharField(max_length=15)

class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=100)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

# Compare this snippet from otp_project/otp_frontend/otp_app/utils.py:
# from django.core.mail import EmailMessage
# from django.core.mail.backends.smtp import EmailBackend