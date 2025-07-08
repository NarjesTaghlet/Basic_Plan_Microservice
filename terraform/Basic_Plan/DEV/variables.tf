variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-2"
}

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  type        = string
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  type        = string
  sensitive   = true
}

variable "aws_session_token" {
  description = "AWS Session Token"
  type        = string
  sensitive   = true
}

variable "user_id" {
  description = "User ID"
  type        = number
}

/*variable "site_id" {
  description = "Site ID"
  type        = number
}
*/
variable "availability_zone" {
  description = "availability zone"
  default = "us-east-2a"

  
}

variable "github_repo_url" {
  description = "GitHub repository URL in the format owner/repo"
  type        = string
}

variable "site_name" {
  description = "Site name"
  type        = string
}

variable "account_id" {
  description = "AWS sub-account ID"
  type        = string
}

variable "docker_image" {
  description = "Docker image for Drupal"
  type        = string
  default = "jesstg/drupal-test:latest"
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token"
 // sensitive   = true
  type = string
  default = ""
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for the domain"
  type = string
  default =""
}

variable "domain_name" {
  description = "nom du domaine"
  type = string
  default = "mat-itops.com"
}


variable "instance_name" {
   description = "Name of the Lightsail instance" 
   type = string 
  // default = "lightsail-${var.user_id}-${var.site_name}"
  default = null
    }

variable "disk_name" {
   description = "Name of the Lightsail disk" 
   type = string 
   default = null
   //default = "disk-${var.user_id}-${var.site_name}" 
   }  


   variable "bundle_id" { 
    description = "Bundle ID for the Lightsail instance" 
    type = string
    default = "micro_3_0"

     } 
