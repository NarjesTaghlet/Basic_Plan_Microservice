
# Create an S3 bucket for Terraform state storage
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-user-${var.user_id}"


  # Prevent accidental deletion of the bucket
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name        = "Terraform State Bucket"
    Environment = "PROD"
  }
}
//add the s3 bucket for the other region for dev env
# Add this resource block to your main.tf
resource "aws_s3_bucket_policy" "state_bucket_policy" {
  bucket = aws_s3_bucket.terraform_state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:role/OrganizationAccountAccessRole"
        }
        Action = [
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = aws_s3_bucket.terraform_state.arn
      }
    ]
  })
}


# Enable versioning for the S3 bucket
resource "aws_s3_bucket_versioning" "terraform_state_versioning" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for the S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_encryption" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access to the S3 bucket
resource "aws_s3_bucket_public_access_block" "terraform_state_public_access" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Create a DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_locks" {
  name           = "terraform-locks-user"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "Terraform Lock Table"
    Environment = "Test"
  }
}

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
          "s3:ListBucket",
          "s3:GetBucketVersioning",  # Add this
          "s3:ListBucketVersions",    # Add this
          "s3:GetObjectVersion",  
        ],
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*"
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
        Effect = "Allow",
        Action = [
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration"
        ],
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*"
        ]
      },
      {
  "Effect": "Allow",
  "Action": [
    "ecr:DeleteRepository",
    "ecr:BatchDeleteImage",
    "ecr:ListImages"
  ],
  "Resource": "*"
}
    ]
  })
}

# Attacher la politique S3/DynamoDB à l'utilisateur
resource "aws_iam_user_policy_attachment" "attach_terraform_backend" {
  # provider   = aws.sub_account
  user       = data.aws_iam_user.existing_user.user_name
  policy_arn = aws_iam_policy.terraform_backend_access.arn
}




