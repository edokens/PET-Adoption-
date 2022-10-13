# Configure the AWS Provider
provider "aws" {
  region = var.region
profile = "Profile name"
shared_credentials_files = ["~/.aws/credentials"]
}
