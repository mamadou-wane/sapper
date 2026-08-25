terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # A separate state key from the main stack, on purpose. The boundary module is
  # durable and hand-applied; terraform/ is torn down at the end of every
  # evidence window. Sharing a state file would couple the two lifecycles.
  backend "s3" {
    bucket       = "sapper-tfstate-mw"
    key          = "sapper/boundary.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
