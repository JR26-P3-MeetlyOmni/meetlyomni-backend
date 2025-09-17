terraform {
  backend "s3" {
    bucket         = "meetlyomni-tf-state-bucket-uat"  
    key            = "uat/terraform.tfstate"        
    region         = "ap-southeast-2"
    dynamodb_table = "terraform-state-locks-uat"
    encrypt        = true
  }
}
