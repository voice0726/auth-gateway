locals {
  db_zone = coalesce(var.zone, "${var.region}-a")
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_compute_network" "auth" {
  name                    = "auth-gateway"
  auto_create_subnetworks = false

  depends_on = [google_project_service.this["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "auth" {
  name          = "auth-gateway"
  ip_cidr_range = var.db_subnet_cidr
  region        = var.region
  network       = google_compute_network.auth.id
}

resource "google_compute_subnetwork" "cloud_run" {
  name          = "auth-gateway-cloud-run"
  ip_cidr_range = var.cloud_run_subnet_cidr
  region        = var.region
  network       = google_compute_network.auth.id
}

resource "google_compute_firewall" "db" {
  name      = "auth-gateway-db"
  network   = google_compute_network.auth.name
  direction = "INGRESS"

  source_ranges = [var.cloud_run_subnet_cidr]
  target_tags   = ["auth-gateway-db"]

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}

resource "google_compute_firewall" "iap_ssh" {
  name      = "auth-gateway-iap-ssh"
  network   = google_compute_network.auth.name
  direction = "INGRESS"

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["auth-gateway-db"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_address" "db" {
  name         = "auth-gateway-db"
  region       = var.region
  subnetwork   = google_compute_subnetwork.auth.id
  address_type = "INTERNAL"
}

resource "google_service_account" "db" {
  account_id   = "gateway-db"
  display_name = "auth-gateway database VM"

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "auth-gateway-db-password"

  replication {
    auto {}
  }

  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db.result
}

resource "google_secret_manager_secret_iam_member" "db_password" {
  secret_id = google_secret_manager_secret.db_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.db.member
}

resource "google_compute_instance" "db" {
  name                      = "auth-gateway-db"
  machine_type              = var.db_machine_type
  zone                      = local.db_zone
  tags                      = ["auth-gateway-db"]
  allow_stopping_for_update = true

  boot_disk {
    auto_delete = true

    initialize_params {
      image = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-12-bookworm-v20261006"
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.auth.id
    network_ip = google_compute_address.db.address

    access_config {}
  }

  metadata_startup_script = templatefile("${path.module}/db-startup.sh.tftpl", {
    db_internal_ip        = google_compute_address.db.address
    db_subnet_cidr        = var.db_subnet_cidr
    cloud_run_subnet_cidr = var.cloud_run_subnet_cidr
    secret_name           = google_secret_manager_secret.db_password.id
  })

  service_account {
    email  = google_service_account.db.email
    scopes = ["cloud-platform"]
  }

  deletion_protection = false

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_service.this,
    google_secret_manager_secret_iam_member.db_password,
    google_secret_manager_secret_version.db_password,
  ]
}
