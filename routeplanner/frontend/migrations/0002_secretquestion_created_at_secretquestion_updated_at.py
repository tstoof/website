# Generated by Django 5.1.4 on 2025-01-06 16:37

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('frontend', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='secretquestion',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='secretquestion',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
