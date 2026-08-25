provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "sapper"
      Environment = "lab"
      Module      = "boundary"
    }
  }
}
