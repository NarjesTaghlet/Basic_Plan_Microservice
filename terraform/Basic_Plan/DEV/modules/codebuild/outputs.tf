output "project_arn" {
  description = "ARN of the CodeBuild project"
  value       = aws_codebuild_project.project.arn
}

output "webhook_secret" {
  description = "Generated secret for the CodeBuild webhook"
  value       = var.enable_webhook ? aws_codebuild_webhook.webhook[0].secret : null
  sensitive   = true
}
# ./modules/codebuild/outputs.tf
output "codebuild_project_name" {
  value = aws_codebuild_project.project.name
}

# In module source_credentials
output "github_credential" {
  value = aws_codebuild_source_credential.github_credential.token
  sensitive = true
}
