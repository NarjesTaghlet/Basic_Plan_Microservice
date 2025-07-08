provider "aws" {
  region = var.aws_region
   access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
  token      = var.aws_session_token
  # Note: Credentials will be provided via environment variables or AWS CLI configuration
}

//added this to satisty upgraded sites (cause their names changed ) 
locals { 
  default_instance_name = "lightsail-${var.user_id}-${var.site_name}"

 default_disk_name = "disk-${var.user_id}-${var.site_name}"

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
# user_data = <<-EOF
#     #!/bin/bash
#     # Install Docker
#     yum install -y docker
#     systemctl start docker
#     systemctl enable docker
#     usermod -aG docker ec2-user

#     # Install CloudWatch Agent
#     yum install -y amazon-cloudwatch-agent
#     cat <<EOT > /opt/aws/amazon-cloudwatch-agent/bin/config.json
#     {
#       "agent": {
#         "metrics_collection_interval": 60,
#         "run_as_user": "root"
#       },
#       "metrics": {
#         "namespace": "Lightsail/Stack",
#         "append_dimensions": {
#           "InstanceId": "$${aws:InstanceName}"
#         },
#         "metrics_collected": {
#           "cpu": {
#             "measurement": ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"],
#             "metrics_collection_interval": 60
#           },
#           "mem": {
#             "measurement": ["mem_used_percent"],
#             "metrics_collection_interval": 60
#           }
#         }
#       }
#     }
#     EOT
#     /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s

#     # Set up the block storage disk
#     # if ! mountpoint -q /mnt/drupal-data; then
#     #   mkfs.ext4 /dev/nvme1n1
#     #    mkdir -p /mnt/drupal-data
#     #    mount /dev/nvme1n1 /mnt/drupal-data
#     #    echo "/dev/nvme1n1 /mnt/drupal-data ext4 defaults,nofail 0 2" >> /etc/fstab
#     # fi
#     # mkdir -p /mnt/drupal-data/sites /mnt/drupal-data/config
#     # chown -R 33:33 /mnt/drupal-data/sites /mnt/drupal-data/config
#   EOF
  
  tags = {
    UserID    = var.user_id
    //SiteID    = var.site_id
    SiteName  = var.site_name
    AccountID = var.account_id
    DeployedAt = timestamp()

  }
}

# Create a Lightsail key pair for SSH access
resource "aws_lightsail_key_pair" "key" {
  name = "key-${var.user_id}-${var.site_name}"
}


# Create a static IP for the instance
resource "aws_lightsail_static_ip" "static_ip" {
  name = "static-ip-${var.user_id}-${var.site_name}"
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
      "db${var.user_id}${var.site_name}",
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
      "db${var.user_id}${var.site_name}",
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
   # Activation des snapshots quotidiens
  #preferred_backup_window   = "06:00-07:00"  # Fenêtre de sauvegarde quotidienne
  #backup_retention_enabled  = true            # Activation de la rétention des sauvegardes


 # Enable daily automatic snapshots
  apply_immediately        = true
  backup_retention_enabled = true
  preferred_backup_window  = "06:00-06:30" # UTC time range for daily snapshots (e.g., 6:00-6:30 AM UTC)

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
  name = "sites/${var.user_id}/${var.site_name}"
  tags = {
    UserID    = var.user_id
    SiteName  = var.site_name
    AccountID = var.account_id
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
    db_name = "db${var.user_id}${var.site_name}"
 
    domain        = var.site_name != "" ? "${var.site_name}.${var.domain_name}" : var.domain_name
  })

  depends_on = [aws_lightsail_database.db]
}

resource "aws_secretsmanager_secret" "ssh_key" {
  name = "ssh/${var.user_id}/${var.site_name}"
  #name="ssh/my-key"
  description = "SSH private key for ${aws_lightsail_instance.instance.name}"
  tags = {
    UserID    = var.user_id
    SiteName  = var.site_name
    AccountID = var.account_id
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
  name    = var.site_name != "" ? "${var.site_name}.${var.domain_name}" : "@"  # e.g., site456.matgo.com or matgo.com
  value   = aws_lightsail_static_ip.static_ip.ip_address  # Dynamic IP after creation
  type    = "A"
  proxied = true
}

# Optional WWW Record (if needed)
resource "cloudflare_record" "www" {
  count   = var.site_name != "" ? 1 : 0  # Only create if using subdomain
  zone_id = var.cloudflare_zone_id
  name    = "www.${var.site_name}.${var.domain_name}"
  value   = "${var.site_name}.${var.domain_name}"
  type    = "CNAME"
  proxied = true
}
*/
# 2. Génération de la clé SSH
/*resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
# 3. Mise à jour de la clé Lightsail
resource "aws_lightsail_key_pair" "key" {
  name       = "key-${var.user_id}-${var.site_name}"
  public_key = tls_private_key.ssh_key.public_key_openssh
}

# 4. Stockage sécurisé de la clé privée
resource "aws_secretsmanager_secret" "ssh_key" {
  name = "ssh/${var.user_id}/${var.site_name}" # Nom unique
}

resource "aws_secretsmanager_secret_version" "ssh_key_version" {
  secret_id     = aws_secretsmanager_secret.ssh_key.id
  secret_string = tls_private_key.ssh_key.private_key_pem # Clé privée valide
}
*/

# GitHub Source Credential for CodeBuild
/*resource "aws_codebuild_source_credential" "github" {
  auth_type   = "PERSONAL_ACCESS_TOKEN"
  server_type = "GITHUB"
  token       = var.github_pat
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

  project_name        = "drupal-deployment-${var.user_id}-${var.site_name}"
  github_repo         = var.github_repo_url
  github_branch       = "main"
  buildspec_path      = "buildspec.yml"
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
    command = "aws codebuild start-build --project-name ${self.triggers.project_name} --source-version main --region us-east-1"
  }

  depends_on = [
    module.codebuild,
    aws_lightsail_instance.instance,
    aws_lightsail_database.db,
    aws_secretsmanager_secret_version.site_secrets_version
  ]
}


# Créer une politique Lightsail complète
/*resource "aws_iam_policy" "lightsail_full_access" {
  name        = "LightsailFullAccess-${var.user_id}"
  description = "Accès complet à Lightsail pour l'utilisateur ${var.user_id}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "lightsail:*",
        Resource = "*"
      }
    ]
  })
}

# Attacher la politique à l'utilisateur existant
resource "aws_iam_user_policy_attachment" "lightsail_access" {
  user       = "user-${var.user_id}"  # Nom de l'utilisateur existant
  policy_arn = aws_iam_policy.lightsail_full_access.arn
}
*/


# Récupérer l'utilisateur existant dans le sous-compte = > to the backend or infra of the sub-account ! 
data "aws_iam_user" "existing_user" {
  //provider = aws.sub_account
  user_name = "user-${var.user_id}"
}

# Créer la politique Lightsail dans le sous-compte
resource "aws_iam_policy" "lightsail_access" {
  //provider    = aws.sub_account
  name        = "LightsailFullAccess-${var.user_id}"
  description = "Accès complet à Lightsail pour ${var.user_id}"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = "lightsail:*",
      Resource = "*"
    }]
  })
}

# Attacher la politique à l'utilisateur existant
resource "aws_iam_user_policy_attachment" "attach_lightsail" {
  //provider   = aws.sub_account
  user       = data.aws_iam_user.existing_user.user_name
  policy_arn = aws_iam_policy.lightsail_access.arn
}


# Policy IAM pour S3 et DynamoDB
resource "aws_iam_policy" "terraform_backend_access" {
  name        = "TerraformBackendAccess-${var.user_id}"
  description = "Accès au bucket S3 et à DynamoDB pour Terraform"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::terraform-state-user",
          "arn:aws:s3:::terraform-state-user/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ],
        Resource = "arn:aws:dynamodb:us-east-1:*:table/terraform-locks-user"
      },
      {
  "Effect": "Allow",
  "Action": [
    "ecr:DeleteRepository",
    "ecr:BatchDeleteImage",
    "ecr:ListImages" ,
     "lightsail:*",
  "lightsail:GetRelationalDatabaseSnapshots",
  "lightsail:DeleteRelationalDatabaseSnapshot"
  ],

  "Resource": "*"
},

    ]
  })
}

# Attacher la politique S3/DynamoDB à l'utilisateur
resource "aws_iam_user_policy_attachment" "attach_terraform_backend" {
  # provider   = aws.sub_account
  user       = data.aws_iam_user.existing_user.user_name
  policy_arn = aws_iam_policy.terraform_backend_access.arn
}
