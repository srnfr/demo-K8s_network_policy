terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = ">= 2.8.0"
    }
  }
}

variable "do_token" {
  type        = string
  description = "DigitalOcean API token. Store it as a sensitive Terraform Cloud variable."
  sensitive   = true
}

variable "entropy" {
  type        = string
  description = "Suffix used to make cluster and VPC names unique."
}

variable "nb_clusters" {
  type        = number
  description = "Number of Kubernetes clusters to create."

  validation {
    condition     = var.nb_clusters >= 1 && var.nb_clusters == floor(var.nb_clusters)
    error_message = "nb_clusters must be a positive whole number."
  }
}

provider "digitalocean" {
  token = var.do_token
}
