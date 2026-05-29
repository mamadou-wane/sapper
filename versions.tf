terraform {
  required_version = ">= 1.11.0"

  backend "s3" {
    bucket       = "sapper-tfstate-mw"
    key          = "sapper/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
