from django import forms

class OTPRequestForm(forms.Form):
    date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    mobile_number = forms.CharField(max_length=15)