# Generated by Django 3.2.9 on 2022-05-05 09:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='passwd',
            name='available',
            field=models.BooleanField(default=True, verbose_name='Available'),
        ),
    ]
