# DigitalOcean API token
## do_token = 
# Resources will be prefixed with this to avoid clashing names
# prefix = "k8s"
# Region where resources should be created
region_name = "fra1"
#domain_name = "randco.eu"
# Droplet size
droplet_size = "s-2vcpu-4gb"
#droplet_image = "docker-20-04"
#ssh_keys = [ "3274777" ]
#tag_name = "demok8"
node_count="2"
# Grab the latest version slug from `doctl kubernetes options versions`
k8s_version="1.25.4-do.0"
##
nb_clusters=1
