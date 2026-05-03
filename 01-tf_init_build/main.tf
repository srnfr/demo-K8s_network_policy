variable "region_name" {
  type        = string
}

variable "droplet_size" {
  type        = string
}
variable "node_count" {
  type        = string
}

data "digitalocean_kubernetes_versions" "latest" {
  version_prefix = ""
}

locals {
  k8s_version = var.k8s_version == "latest" ? data.digitalocean_kubernetes_versions.latest.latest_version : var.k8s_version
}

variable "k8s_version" {
  type        = string
}


####
# VPC dédié par cluster pour éviter les overlaps
resource "digitalocean_vpc" "vpc" {
  count    = var.nb_clusters
  name     = "vpc-k8-do-grp${count.index}-${var.entropy}"
  region   = var.region_name

 # Associer chaque cluster à son VPC dédié
  vpc_uuid = digitalocean_vpc.vpc[count.index].id

}

resource "digitalocean_kubernetes_cluster" "cluster" {
  count = var.nb_clusters
  name    = "k8-do-grp${count.index}-${var.entropy}"
  region  = var.region_name
  version = local.k8s_version

  # This default node pool is mandatory
  node_pool {
    name       = "node"
    size       = var.droplet_size
    auto_scale = false
    node_count = var.node_count
  }

  # Chaque cluster a sa propre plage /20 : 10.150.0.0/20, 10.151.0.0/20, etc.
  ip_range = "10.${150 + count.index}.0.0/20"
}

resource "digitalocean_project" "trainingk8" {
  name        = "trainingk8"
  description = "Projet pour la formation"
  purpose     = "Web Application"
  environment = "Development"
  resources   = digitalocean_kubernetes_cluster.cluster[*].urn
}
