# Generated by Django 5.1.7 on 2025-04-01 18:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('deploy', '0002_alter_vmdeployment_cluster_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='vmdeployment',
            name='job_id',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='vmdeployment',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
    ]
