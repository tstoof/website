# Generated by Django 5.1.4 on 2025-01-13 16:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0005_passwordresetattempt'),
    ]

    operations = [
        migrations.DeleteModel(
            name='PasswordResetAttempt',
        ),
    ]
