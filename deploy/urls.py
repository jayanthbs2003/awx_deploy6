# deploy/urls.py
from django.urls import path
from .views import (
    login_page, authenticate_vcenter, deploy_vm_view, create_vm_view, vm_list_view,
    load_clusters, load_datastores, load_networks, load_datacenters, load_folders,
    load_templates, vm_list, create_vm, delete_vms, recent_activity,host_list,get_vm_summary,launch_remote_console,vm_details_view,power_on_vm,power_off_vm,convert_to_template,vm_distribution, vm_new_list_view,vm_category_list
)

urlpatterns = [
    path('login/', login_page, name='login_page'),
    path('authenticate-vcenter/', authenticate_vcenter, name='authenticate_vcenter'),
    path('deploy_vm/', deploy_vm_view, name='deploy_vm'),
    path('create-vm/', create_vm_view, name='create-vm'),
    path('vm-list/', vm_list_view, name='vm_list_view'),
    path('vms/', vm_list, name='vm_list'),
    path('load-clusters/', load_clusters, name='load_clusters'),
    path('load-datastores/', load_datastores, name='load_datastores'),
    path('load-networks/', load_networks, name='load_networks'),
    path('load-datacenters/', load_datacenters, name='load_datacenters'),
    path('load-folders/', load_folders, name='load_folders'),
    path('load-templates/', load_templates, name='load_templates'),
    path('create_vm/', create_vm, name='create_vm'),
    path('delete-vms/', delete_vms, name='delete_vms'),  # New endpoint
    path('recent-activity/', recent_activity, name='recent_activity'),  # New endpoint
    path('hosts/', host_list, name='host_list'),  # New route for hosts
    # Added for VM Summary
    path('vm-summary/', get_vm_summary, name='vm_summary'),
    path('launch-remote-console/<str:vm_name>/', launch_remote_console, name='launch_remote_console'),
    path('vm-details/', vm_details_view, name='vm_details'),
    path('power-on/<str:vm_name>/', power_on_vm, name='power_on_vm'),
    path('power-off/<str:vm_name>/', power_off_vm, name='power_off_vm'),
    path('convert-to-template/<str:vm_name>/', convert_to_template, name='convert_to_template'),
    path('api/vm-distribution', vm_distribution, name='vm-distribution'),
    path('vm-new-list/', vm_new_list_view, name='vm_new_list'),
    path('vm-category-list/<str:category>/', vm_category_list, name='vm_category_list'),
    
    
    
]