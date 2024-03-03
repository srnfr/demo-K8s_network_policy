variable "region_name" {
  type        = string
}

variable "droplet_size" {
  type        = string
}
variable "node_count" {
  type        = string
}
variable "k8s_version" {
  type        = string
}

# Cette variable est maintenant stockée dans un env de Terraform
# variable "nb_clusters" {
#  type      = number
#}

####

resource "digitalocean_kubernetes_cluster" "cluster" {
  count = var.nb_clusters
  name    = "k8-do-grp${count.index}-${var.entropy}"
  region  = var.region_name
  version = var.k8s_version

  # This default node pool is mandatory
  node_pool {
    name       = "node"
    size       = var.droplet_size
    auto_scale = false
    node_count = var.node_count
  }
}

resource "digitalocean_project" "trainingk8" {
  name        = "trainingk8"
  description = "Projet pour la formation"
  purpose     = "Web Application"
  environment = "Development"
  resources   = digitalocean_kubernetes_cluster.cluster[*].urn
}
