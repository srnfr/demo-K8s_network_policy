variable "region_name" {
  type        = string
  description = "DigitalOcean region where the clusters are created."
}

variable "droplet_size" {
  type        = string
  description = "DigitalOcean node size for each Kubernetes node pool."
}

variable "node_count" {
  type        = number
  description = "Number of nodes in each Kubernetes cluster. Set this in Terraform Cloud."
  default     = 3

  validation {
    condition     = var.node_count >= 1 && var.node_count == floor(var.node_count)
    error_message = "Node count must be a positive whole number."
  }
}

variable "project_name" {
  type        = string
  description = "Existing DigitalOcean project to which the Kubernetes clusters are assigned. Set this in Terraform Cloud."

  validation {
    condition     = trimspace(var.project_name) != ""
    error_message = "Project name must not be empty."
  }
}

data "digitalocean_kubernetes_versions" "latest" {
  version_prefix = ""
}

locals {
  k8s_version = var.k8s_version == "latest" ? data.digitalocean_kubernetes_versions.latest.latest_version : var.k8s_version
}

variable "k8s_version" {
  type        = string
  description = "Kubernetes version, or latest to use the latest supported version."
}


####
# VPC dédié par cluster pour éviter les overlaps
resource "digitalocean_vpc" "vpc" {
  count  = var.nb_clusters
  name   = "vpc-k8-do-grp${count.index}-${var.entropy}"
  region = var.region_name

  # Chaque cluster a sa propre plage 
  ip_range = cidrsubnet("10.170.0.0/16", 4, count.index)

}

resource "digitalocean_kubernetes_cluster" "cluster" {
  count   = var.nb_clusters
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

  # Associer chaque cluster à son VPC dédié
  vpc_uuid = digitalocean_vpc.vpc[count.index].id

  # Subnets pods et services distincts par cluster
  cluster_subnet = cidrsubnet("10.180.0.0/16", 4, count.index)
  service_subnet = cidrsubnet("10.190.0.0/16", 4, count.index)

}

data "digitalocean_project" "lab" {
  name = var.project_name
}

resource "digitalocean_project_resources" "lab" {
  project   = data.digitalocean_project.lab.id
  resources = digitalocean_kubernetes_cluster.cluster[*].urn
}
