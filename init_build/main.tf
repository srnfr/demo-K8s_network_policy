variable "region_name" {
  type        = string
}
variable "domain_name" {
  type        = string
}
variable "droplet_size" {
  type        = string
}
variable "droplet_image" {
  type        = string
}

variable "node_count" {
  type        = string
}

resource "digitalocean_kubernetes_cluster" "kubernetes_cluster" {
  name    = "terraform-do-cluster"
  region  = var.region_name
  ##version = "1.18.6-do.0"

  # This default node pool is mandatory
  node_pool {
    name       = "default-pool"
    size       = var.droplet_size
    auto_scale = false
    node_count = var.node_count
  }


resource "digitalocean_record" "demok8s" {
  domain = var.domain_name
  type   = "A"
  name   = "demok8s"
  value  = digitalocean_droplet.docker.ipv4_address
}
