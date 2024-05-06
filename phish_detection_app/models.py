from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _
from django.conf import settings
import secrets
from django.utils import timezone
import datetime

class URL(models.Model):
    url = models.URLField(max_length=200)
    result = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # generated_by_input_url = models.BooleanField(default=False)  # New field
    def __str__(self):
        return f"{self.url} -{self.result} -{self.timestamp}"



