from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import SecretQuestion
from django import forms
from django.contrib.auth.forms import SetPasswordForm
import re

class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
        return user
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        username = self.cleaned_data.get('username')

        # Ensure password meets the complexity requirements
        if not re.fullmatch(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$', password):
            raise ValidationError(
                ""
            )

        # Prohibit username from being part of the password
        if username and username.lower() in password.lower():
            raise ValidationError('Password must not contain your username.')

        # Separate digits and letters, treating letters case-insensitively
        digits = [char for char in password if char.isdigit()]
        letters = [char.lower() for char in password if char.isalpha()]  # Convert to lowercase

        # Ensure all digits are not the same
        if len(digits) > 1 and len(set(digits)) == 1:
            raise ValidationError('Password cannot consist of the same digit repeated.')

        # Ensure all letters are not the same (case-insensitive)
        if letters and len(set(letters)) == 1:
            raise ValidationError('Password cannot consist of the same letter repeated, ignoring case.')

        return password

    def clean(self):
        cleaned_data = super(CustomUserCreationForm, self).clean()  # Correctly call the parent form's clean() method

        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        # Ensure the passwords match
        if password1 and password2 and password1 != password2:
            raise ValidationError('Passwords do not match.')

        return cleaned_data



class SecretQuestionForm(forms.Form):
    username = forms.CharField(max_length=255, required=True)
    question = forms.CharField(max_length=255, required=False)  # Only required for registration
    answer = forms.CharField(max_length=255, min_length=64, required=True)
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput, required=False)  # Required for reset
    new_password2 = forms.CharField(label="Confirm new password", widget=forms.PasswordInput, required=False)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Optional user argument
        self.is_registration = kwargs.pop('is_registration', False)  # Flag to indicate registration
        super().__init__(*args, **kwargs)

        if not self.is_registration:
            # During password reset, the question field is readonly
            self.fields['question'].widget.attrs['readonly'] = True

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        answer = cleaned_data.get('answer')

        if self.is_registration:
            # For registration, ensure the username does not already exist
            if User.objects.filter(username=username).exists():
                raise forms.ValidationError("A user with this username already exists.")

            # Ensure the question is provided during registration
            question = cleaned_data.get('question')
            if not question:
                raise forms.ValidationError("Please provide a secret question.")
        else:
            # For password reset, validate the username and secret question answer
            try:
                user = User.objects.get(username=username)
                secret_question = SecretQuestion.objects.get(user=user)

                if secret_question.answer != answer:
                    raise forms.ValidationError("Incorrect secret answer.")
                # Store the user instance for resetting the password later
                self.user = user
            except User.DoesNotExist:
                raise forms.ValidationError("No user found with this username.")
            except SecretQuestion.DoesNotExist:
                raise forms.ValidationError("No secret question set for this user.")

            # Validate new password fields during password reset
            new_password1 = cleaned_data.get('new_password1')
            new_password2 = cleaned_data.get('new_password2')

            if new_password1 or new_password2:  # If one is set, validate both
                if new_password1 != new_password2:
                    raise forms.ValidationError("Passwords do not match.")
                if not new_password1 or not new_password2:
                    raise forms.ValidationError("Both password fields are required.")

        return cleaned_data

    def save(self):
        """
        Save method for password reset.
        Only used during password reset, not during registration.
        """
        if not self.is_registration and self.user:
            new_password = self.cleaned_data.get('new_password1')
            if new_password:
                self.user.set_password(new_password)
                self.user.save()



class ResetPasswordForm(SetPasswordForm):
    """Form for setting a new password with validation rules"""

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)  # Capture the user from kwargs
        super().__init__(*args, **kwargs)

    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')

        # Ensure password meets the complexity requirements
        if not re.fullmatch(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$', password):
            raise ValidationError(
                'Password must be at least 8 characters long, contain at least one uppercase letter, '
                'one lowercase letter, one number, and one special character.'
            )

        # Prohibit reuse of username in the password
        username = self.user.username.lower() if self.user else None
        if username and username in password.lower():
            raise ValidationError('Password must not contain your username.')
        
        # Check for repeated characters
        digits = [char for char in password if char.isdigit()]
        letters = [char.lower() for char in password if char.isalpha()]

        if len(digits) > 1 and len(set(digits)) == 1:
            raise ValidationError('Password cannot consist of the same digit repeated.')
        if letters and len(set(letters)) == 1:
            raise ValidationError('Password cannot consist of the same letter repeated, ignoring case.')

        return password


class SecretAnswerLoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    secret_answer = forms.CharField(widget=forms.PasswordInput, max_length=255, min_length=64)