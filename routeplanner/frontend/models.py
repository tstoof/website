# frontend/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password

class SecretQuestion(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    question = models.CharField(max_length=255)
    answer = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set to now when created

    def __str__(self):
        return f"Secret question for {self.user.username}"
    
    def save(self, *args, **kwargs):
        if not self.answer.startswith('pbkdf2_sha256$'):  # Prevent double hashing
            self.answer = make_password(self.answer)
        super().save(*args, **kwargs)


class RouteData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='routes')
    name = models.CharField(max_length=255)  # Optional: name or title for the route
    data = models.JSONField()  # Stores route data as JSON
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Route '{self.name}' for {self.user.username}"





