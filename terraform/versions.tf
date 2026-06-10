terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # D2: Phase 1 root state key. Bootstrap remains local.
  backend "s3" {
    bucket       = "sapper-tfstate-mw"
    key          = "sapper/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
