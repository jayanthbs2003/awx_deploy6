# Generated by Django 5.1.7 on 2025-07-03 07:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('deploy', '0005_vmactivity_created_at_alter_vmdeployment_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vmdeployment',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
    ]
