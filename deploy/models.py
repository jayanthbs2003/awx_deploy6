from django.db import models

class VMDeployment(models.Model):
    vm_name = models.CharField(max_length=255)
    cluster = models.CharField(max_length=255)
    datastore = models.CharField(max_length=255)
    network = models.CharField(max_length=255)
    template = models.CharField(max_length=255)
    status = models.CharField(max_length=50, default="Pending")
    created_at = models.DateTimeField(auto_now_add=True, null=True)  # If not present, add this
    job_id = models.IntegerField(null=True, blank=True)  # Add this field

    def __str__(self):
        return f"{self.vm_name} - {self.status}"


class VMActivity(models.Model):
    vm_name = models.CharField(max_length=255)
    message = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set on creation
    def __str__(self):
        return f"{self.vm_name} - {self.message} at {self.timestamp}"
    
class Meta:
        db_table = "deploy_vmactivity"