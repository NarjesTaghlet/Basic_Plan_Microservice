output "instance_public_ip" {
  description = "Public IP of the Lightsail instance"
  value       = aws_lightsail_static_ip.static_ip.ip_address
}

output "database_endpoint" {
  description = "Endpoint of the Lightsail database"
  value       = aws_lightsail_database.db.master_endpoint_address
}

output "database_port" {
  description = "Port of the Lightsail database"
  value       = aws_lightsail_database.db.master_endpoint_port
}

output "database_name" {
  description = "Name of the database"
  value       = "db-${var.user_id}-${var.site_name}"
}

output "database_username" {
  description = "Username for the database"
  value       = aws_lightsail_database.db.master_username
}

output "database_password" {
  description = "Password for the database"
  value       = aws_lightsail_database.db.master_password
  sensitive   = true
}

output "dns_record" {
  description = "Primary Cloudflare DNS record for this instance"
  value       = var.site_name != "" ? "${var.site_name}.${var.domain_name}" : var.domain_name
}

output "www_dns_record" {
  description = "WWW Cloudflare DNS record (if created)"
  value       = var.site_name != "" ? "www.${var.site_name}.${var.domain_name}" : null
}

output "instance_name" {
  description = "Name of the Lightsail instance (for CloudWatch metrics)"
  value       = aws_lightsail_instance.instance.name
}

output "ssh"{
  description = "ssh key of the instance"
  value = aws_lightsail_key_pair.key.private_key
}


output "site_secrets_arn" {
  description = "ARN of the site secrets"
  value       = aws_secretsmanager_secret.site_secrets.arn
}

output "ssh_key_secret_arn" {
  description = "ARN of the SSH key secret"
  value       = aws_secretsmanager_secret.ssh_key.arn
}
//shoiuld add the ssh key 


output "codebuild_project_arn" {
  description = "ARN of the CodeBuild project"
  value       = module.codebuild.project_arn
}


/*output "webhook_secret" {
  description = "Generated secret for the GitHub webhook"
  value       = module.codebuild.webhook_secret
  sensitive   = true
}
*/
output "codebuild_project_name" {
  value = module.codebuild.codebuild_project_name
}

output "token_github" {
 value       = module.codebuild.github_credential
 sensitive = true
}


