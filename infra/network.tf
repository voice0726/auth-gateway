resource "google_compute_network" "auth" {
  name                    = "auth-gateway"
  auto_create_subnetworks = false

  depends_on = [google_project_service.this["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "cloud_run" {
  name          = "auth-gateway-cloud-run"
  ip_cidr_range = var.cloud_run_subnet_cidr
  region        = var.region
  network       = google_compute_network.auth.id
}
