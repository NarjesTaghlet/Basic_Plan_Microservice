variable "project_name" {
  description = "Name of the CodeBuild project"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository in the format owner/repo"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch to trigger builds"
  type        = string
  default     = "dev"
}

variable "buildspec_path" {
  description = "Path to the buildspec file in the repository"
  type        = string
  default     = "buildspec_dev.yml"
}

variable "aws_region" {
  description = "AWS region for the CodeBuild project"
  type        = string
  default = "us-east-2"
}

variable "user_id" {
  description = "User ID for the deployment"
  type        = number
}

variable "site_name" {
  description = "Site name for the deployment"
  type        = string
}

variable "target_ip" {
  description = "Target instance IP"
  type        = string
}

variable "ssh_user" {
  description = "SSH user for the instance"
  type        = string
}

variable "docker_image" {
  description = "Docker image for the Drupal application"
  type        = string
   default = "jesstg/drupal-app:latest"

}

variable "db_port" {
  description = "Database port"
  type        = string
}

variable "enable_webhook" {
  description = "Whether to enable the GitHub webhook"
  type        = bool
  default     = true
}

variable "webhook_secret" {
  description = "Secret for the GitHub webhook"
  type        = string
  sensitive   = true
}