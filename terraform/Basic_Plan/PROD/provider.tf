terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
            version = "5.0.0" # Version spécifique

    }
   /* cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }

     tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    */
  }
  //we should create a backend s3 bucket & db for every user when creating its aws account
  //and put it there as a distant backend to prevent destruction of ressources ! 

  
  backend "s3" {
    bucket         = "terraform-state-user" # Replace with actual bucket name or use variables
    key            = "sites/${var.user_id}/${var.site_name}/terraform.tfstate"
    region         =  "us-east-1" # Replace with your AWS region, e.g., "us-east-1"
    //dynamodb_table = "terraform-locks-user" # Replace with actual table name
        use_lockfile = true

  }

  /*backend "local" {
    path = "terraform.tfstate"
  }
  */
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
  token      = var.aws_session_token
  alias = "sub_account"
}

# Configure the Cloudflare provider
/*provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
*/
