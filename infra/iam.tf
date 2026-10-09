resource "google_service_account" "runtime" {
  account_id   = "gateway-runtime"
  display_name = "auth-gateway runtime"

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret" "config" {
  secret_id = "gateway-config"

  replication {
    auto {}
  }

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_iam_member" "runtime_config" {
  secret_id = google_secret_manager_secret.config.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.runtime.member
}

resource "google_service_account" "scheduler" {
  account_id   = "gateway-scheduler"
  display_name = "auth-gateway cleanup scheduler"

  depends_on = [google_project_service.this]
}

resource "google_service_account" "deploy" {
  account_id   = "gateway-deploy"
  display_name = "auth-gateway GitHub Actions deploy"

  depends_on = [google_project_service.this]
}

resource "google_project_iam_member" "deploy_run" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = google_service_account.deploy.member
}

resource "google_artifact_registry_repository_iam_member" "deploy_push" {
  repository = google_artifact_registry_repository.gateway.name
  location   = var.artifact_region
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.deploy.member
}

resource "google_service_account_iam_member" "deploy_act_as_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.deploy.member
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github"

  depends_on = [google_project_service.this]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = join(" && ", [
    "assertion.repository == \"${var.github_repository}\"",
    "assertion.ref == \"refs/heads/main\"",
    "assertion.workflow_ref == \"${var.github_repository}/.github/workflows/deploy.yml@refs/heads/main\"",
  ])

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "deploy_wif" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}
