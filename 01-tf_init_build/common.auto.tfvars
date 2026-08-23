# DigitalOcean API token
## do_token = 
# Resources will be prefixed with this to avoid clashing names
# prefix = "k8s"
# Region where resources should be created
region_name = "fra1"
# Droplet size
droplet_size = "s-4vcpu-8gb"
#droplet_image = "docker-20-04"
#ssh_keys = [ "3274777" ]
#tag_name = "demok8"

# Le nombre de nœuds est une variable Terraform Cloud : node_count.
# Ne pas la définir ici : une valeur dans un *.auto.tfvars écraserait la valeur du workspace TFC.

# Grab the latest version slug from `doctl kubernetes options versions`
k8s_version = "latest"

##
## Maintenant utilisée en env Terraform
## nb_clusters=3
