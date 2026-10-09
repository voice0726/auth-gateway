resource "google_artifact_registry_repository" "gateway" {
  repository_id = "auth-gateway"
  location      = var.artifact_region
  format        = "DOCKER"

  depends_on = [google_project_service.this]
}
