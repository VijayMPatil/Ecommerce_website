# Generated by Django 4.1.6 on 2023-02-12 11:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Authapp', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Contact',
        ),
        migrations.DeleteModel(
            name='Orders',
        ),
        migrations.DeleteModel(
            name='OrderUpdate',
        ),
        migrations.DeleteModel(
            name='Product',
        ),
    ]