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


# class RouteData(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='routes')
#     name = models.CharField(max_length=255)  # Optional: name or title for the route
#     data = models.JSONField()  # Stores route data as JSON
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return f"Route '{self.name}' for {self.user.username}"


from django.conf import settings
from cryptography.fernet import Fernet

class RouteData(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    data = models.TextField()  # Encrypted route data

    # Encryption methods
    def encrypt_data(self, raw_data):
        cipher = Fernet(settings.ENCRYPTION_KEY)
        return cipher.encrypt(raw_data.encode()).decode()

    def decrypt_data(self):
        cipher = Fernet(settings.ENCRYPTION_KEY)
        return cipher.decrypt(self.data.encode()).decode()
    



def generate_key():
    return Fernet.generate_key()

# Encrypt data (return as bytes)
def encrypt_data(raw_data):
    key = settings.ENCRYPTION_KEY  # Make sure to use your actual key here.
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(raw_data.encode())  # Ensure the data is in bytes
    return encrypted_data

# Decrypt data (return as string)
def decrypt_data(encrypted_data):
    key = settings.ENCRYPTION_KEY  # Use the same key used for encryption
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()  # Decoding back to string
    return decrypted_data