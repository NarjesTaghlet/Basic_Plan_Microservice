provider "aws" {
  region = var.aws_region
   access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
  token      = var.aws_session_token
  # Note: Credentials will be provided via environment variables or AWS CLI configuration
}

//added this to satisty upgraded sites (cause their names changed ) 
locals { 
  default_instance_name = "dev-lightsail-${var.user_id}-${var.site_name}"

 default_disk_name = "dev-disk-${var.user_id}-${var.site_name}"

   }

resource "aws_lightsail_instance" "instance" {
  //provider = aws.sub_account
  key_pair_name = aws_lightsail_key_pair.key.name
  name              = coalesce(var.instance_name, local.default_instance_name)
  availability_zone = "${var.availability_zone}"
  blueprint_id      = "amazon_linux_2"
  bundle_id         = var.bundle_id
  add_on {
    type          = "AutoSnapshot"
    snapshot_time = "06:00"
    status        = "Enabled"
  }


  //user_data = "sudo yum update -y && sudo yum install -y docker && sudo systemctl start docker && sudo systemctl enable docker && sudo usermod -aG docker ec2-user && sudo mkdir -p /var/www/html &&  | sudo tee /var/www/html/index.html"
  user_data = "sudo yum update -y && sudo yum install -y docker && sudo systemctl start docker && sudo systemctl enable docker && sudo usermod -aG docker ec2-user && sudo mkdir -p /var/www/html && echo '<!DOCTYPE html><html><body><h1>Docker Host Ready</h1></body></html>' | sudo tee /var/www/html/index.html"

  
  tags = {
    UserID    = var.user_id
    //SiteID    = var.site_id
    SiteName  = var.site_name
    AccountID = var.account_id
    DeployedAt = timestamp()
    Environment = "dev"

  }
}

# Create a Lightsail key pair for SSH access
resource "aws_lightsail_key_pair" "key" {
  name = "key-${var.user_id}-${var.site_name}-dev"
}


# Create a static IP for the instance
resource "aws_lightsail_static_ip" "static_ip" {
  name = "static-ip-${var.user_id}-${var.site_name}-dev"
}

# Attach the static IP to the instance
resource "aws_lightsail_static_ip_attachment" "static_ip_attachment" {
  static_ip_name = aws_lightsail_static_ip.static_ip.name
  instance_name  = aws_lightsail_instance.instance.name
}

# Open ports 80 (HTTP) and 22 (SSH)
resource "aws_lightsail_instance_public_ports" "ports" {
  instance_name = aws_lightsail_instance.instance.name

  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
  }

  port_info {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80
  }

  port_info {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443
  }
}

# Create a Lightsail block storage disk for persistence (8 GB)
resource "aws_lightsail_disk" "disk" {
  //provider = aws.sub_account
  name              =  coalesce(var.disk_name, local.default_disk_name)
  size_in_gb        = 8
  availability_zone = "${var.availability_zone}"

  tags = {
    UserID    = var.user_id
    //SiteID    = var.site_id
    SiteName  = var.site_name
    AccountID = var.account_id
    DeployedAt = timestamp()
  }
}

# Attach the disk to the instance
resource "aws_lightsail_disk_attachment" "disk_attachment" {
  disk_name     = aws_lightsail_disk.disk.name
  instance_name = aws_lightsail_instance.instance.name
  disk_path     = "/dev/xvdf"
}

# Create a Lightsail managed MySQL database (smallest size: micro_2_0)
resource "aws_lightsail_database" "db" {
  // relational_database_name = "drupaldb-${var.user_id}_${var.site_id}"
 // provider = aws.sub_account
  relational_database_name = substr(
    replace(
      "db${var.user_id}${var.site_name}dev",
      "/[^a-zA-Z0-9-]/", "-"
    ),
    0, 255
  )
  availability_zone        = "${var.availability_zone}"
  blueprint_id             = "mysql_8_0"
  bundle_id                = "micro_2_0"
 // master_database_name     = "db-${var.user_id}_${var.site_name}"
 master_database_name     = substr(
    replace(
      "db${var.user_id}${var.site_name}dev",
      "/[^a-zA-Z0-9_]/", "_"
    ),
    0, 64
  )
  master_username          = "user"
  master_password          = random_password.db_password.result
  

  tags = {
    UserID    = var.user_id
   // SiteID    = var.site_id
    SiteName  = var.site_name
    //AccountID = var.account_id
    DeployedAt = timestamp()
  }

  # Ensure a final snapshot is taken
  skip_final_snapshot    = true
  
}

# Generate a random password for the database
resource "random_password" "db_password" {
  length  = 16
  special = true
  override_special = "!#$%&*()-_=+"

}



# Generate a random suffix to ensure secret name uniqueness
/*resource "random_string" "secret_suffix" {
  length  = 6
  special = false
  upper   = false
}
*/
//Store creds in the secrets manager 
resource "aws_secretsmanager_secret" "site_secrets" {
  name = "sites/dev/${var.user_id}/${var.site_name}"
  tags = {
    UserID    = var.user_id
    SiteName  = var.site_name
    AccountID = var.account_id
    Environment = "dev"
  }
}

resource "aws_secretsmanager_secret_version" "site_secrets_version" {
  secret_id = aws_secretsmanager_secret.site_secrets.id
  secret_string = jsonencode({
    instance_name = aws_lightsail_instance.instance.name
    public_ip     = aws_lightsail_static_ip.static_ip.ip_address
    db_endpoint   = aws_lightsail_database.db.master_endpoint_address
    db_username   = "user"
    db_password   = aws_lightsail_database.db.master_password
    disk_name = aws_lightsail_disk.disk.name
    db_name = "db${var.user_id}${var.site_name}dev"
 
    domain        = var.site_name != "" ? "${var.site_name}dev.${var.domain_name}" : var.domain_name
  })

  depends_on = [aws_lightsail_database.db]
}

resource "aws_secretsmanager_secret" "ssh_key" {
  name = "ssh/dev/${var.user_id}/${var.site_name}"
  #name="ssh/my-key"
  description = "SSH private key for ${aws_lightsail_instance.instance.name}"
  tags = {
    UserID    = var.user_id
    SiteName  = var.site_name
    AccountID = var.account_id
    Environment = "dev"
  }
}


resource "aws_secretsmanager_secret_version" "ssh_key_version" {
  secret_id = aws_secretsmanager_secret.ssh_key.id
  secret_string = aws_lightsail_key_pair.key.private_key
}


#Add cloudflare !

# Cloudflare DNS Record (Dynamic)
/*resource "cloudflare_record" "instance_record" {
  zone_id = var.cloudflare_zone_id
  name    = var.site_name != "" ? "${var.site_name}dev.${var.domain_name}" : "@"  # e.g., site456.matgo.com or matgo.com
  value   = aws_lightsail_static_ip.static_ip.ip_address  # Dynamic IP after creation
  type    = "A"
  proxied = true
}

# Optional WWW Record (if needed)
resource "cloudflare_record" "www" {
  count   = var.site_name != "" ? 1 : 0  # Only create if using subdomain
  zone_id = var.cloudflare_zone_id
  name    = "www.${var.site_name}dev.${var.domain_name}"
  value   = "${var.site_name}.${var.domain_name}"
  type    = "CNAME"
  proxied = true
}
*/
# Generate a random string for the webhook secret
resource "random_string" "webhook_secret" {
  length  = 32
  special = false
}

# CodeBuild Module
module "codebuild" {
  source = "./modules/codebuild"

  project_name        = "dp-dev-${var.user_id}-${var.site_name}"
  github_repo         = var.github_repo_url
  github_branch       = "dev"
  buildspec_path      = "buildspec_dev.yml"
  aws_region          = var.aws_region
  user_id             = var.user_id
  site_name           = var.site_name
  target_ip           = aws_lightsail_static_ip.static_ip.ip_address
  ssh_user            = "ec2-user"
  docker_image        = var.docker_image
  db_port             = "3306"
  enable_webhook      = true
  webhook_secret      = random_string.webhook_secret.result
  #depends_on = [module.codebuild.github_credential]

}


resource "null_resource" "initial_codebuild_run" {
  triggers = {
    project_name = module.codebuild.codebuild_project_name
  }

  provisioner "local-exec" {
    command = "aws codebuild start-build --project-name ${self.triggers.project_name} --source-version dev --region us-east-2"
  }

  depends_on = [
    module.codebuild,
    aws_lightsail_instance.instance,
    aws_lightsail_database.db,
    aws_secretsmanager_secret_version.site_secrets_version
  ]
}

