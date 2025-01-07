from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import SecretQuestion
from django import forms
from django.contrib.auth.forms import SetPasswordForm


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, label='Email')

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email
    


from django import forms
from django.contrib.auth.models import User
from .models import SecretQuestion

class SecretQuestionForm(forms.Form):
    username = forms.CharField(max_length=255, required=True)
    question = forms.CharField(max_length=255, required=False)  # Only required for registration
    answer = forms.CharField(max_length=255, required=True)
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
    """Form for setting a new password"""
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput)
    new_password2 = forms.CharField(label="Confirm new password", widget=forms.PasswordInput)

