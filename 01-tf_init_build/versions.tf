terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
      version = ">= 2.8.0"
    }
  }
}

variable "do_token" {}

variable "entropy" {}

variable "nb_clusters" {}

provider "digitalocean" {
  token = var.do_token
}
