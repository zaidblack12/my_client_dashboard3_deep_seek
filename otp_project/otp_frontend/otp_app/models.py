from django.db import models
from django.contrib.auth.models import User

class Client(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile_number = models.CharField(max_length=15)
    email_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=[('user', 'User'), ('admin', 'Admin')], default='user')

    def __str__(self):
        return self.user.username
    
    
class OTPRequestLog(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    date_requested = models.DateField()
    mobile_number = models.CharField(max_length=15)
    status = models.CharField(max_length=20, default='Pending')

    def __str__(self):
        return f"{self.client.user.username} - {self.date_requested}"

class AccessHistory(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.client.user.username} - {self.action}"