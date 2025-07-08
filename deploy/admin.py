from django.contrib import admin
from .models import VMDeployment

@admin.register(VMDeployment)
class VMDeploymentAdmin(admin.ModelAdmin):
    list_display = ("vm_name", "cluster", "datastore", "network", "status", "created_at")
    search_fields = ("vm_name", "cluster", "status")
    list_filter = ("status", "created_at")

