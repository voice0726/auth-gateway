output "db_host" {
  value = google_compute_address.db.address
}

output "db_password" {
  value     = random_password.db.result
  sensitive = true
}

output "image_repository" {
  value = "${var.artifact_region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.gateway.repository_id}"
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}

output "deploy_service_account" {
  value = google_service_account.deploy.email
}

output "gateway_url" {
  value = var.deploy_workloads ? google_cloud_run_v2_service.gateway[0].uri : null
}
