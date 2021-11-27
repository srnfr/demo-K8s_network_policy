# main.tf
# Configure the DigitalOcean Provider
provider "digitalocean" {
  version = "~> 1.22"
  # token   = var.do_token # This is the DO API token.
  # Alternatively, this can also be specified using environment variables ordered by precedence:
  #   DIGITALOCEAN_TOKEN, 
  #   DIGITALOCEAN_ACCESS_TOKEN
}
