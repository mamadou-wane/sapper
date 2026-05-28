provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "Dev"
      Project     = "MultiAZ-Web-App"
      ManagedBy   = "Terraform"
    }
  }
}
