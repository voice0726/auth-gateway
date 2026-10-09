locals {
  config_mount = "/secrets"
}

resource "google_cloud_run_v2_service" "gateway" {
  count = var.deploy_workloads ? 1 : 0

  name                 = "auth-gateway"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  deletion_protection  = true
  invoker_iam_disabled = true

  template {
    service_account = google_service_account.runtime.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }

    containers {
      image = var.image

      ports {
        container_port = 8800
      }

      env {
        name  = "CONFIG_PATH"
        value = "${local.config_mount}/config.yaml"
      }

      volume_mounts {
        name       = "config"
        mount_path = local.config_mount
      }

    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"

      network_interfaces {
        network    = google_compute_network.auth.id
        subnetwork = google_compute_subnetwork.cloud_run.id
      }
    }

    volumes {
      name = "config"
      secret {
        secret = google_secret_manager_secret.config.secret_id
        items {
          version = "latest"
          path    = "config.yaml"
        }
      }
    }

  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }

  depends_on = [google_secret_manager_secret_iam_member.runtime_config]
}

resource "google_cloud_run_v2_job" "task" {
  for_each = var.deploy_workloads ? toset(["migrate", "cleanup"]) : toset([])

  name                = "auth-gateway-${each.key}"
  location            = var.region
  deletion_protection = true

  template {
    template {
      service_account = google_service_account.runtime.email
      max_retries     = 0

      containers {
        image   = var.image
        command = ["/app/${each.key}"]

        env {
          name  = "CONFIG_PATH"
          value = "${local.config_mount}/config.yaml"
        }

        volume_mounts {
          name       = "config"
          mount_path = local.config_mount
        }

      }

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"

        network_interfaces {
          network    = google_compute_network.auth.id
          subnetwork = google_compute_subnetwork.cloud_run.id
        }
      }

      volumes {
        name = "config"
        secret {
          secret = google_secret_manager_secret.config.secret_id
          items {
            version = "latest"
            path    = "config.yaml"
          }
        }
      }

    }
  }

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }

  depends_on = [google_secret_manager_secret_iam_member.runtime_config]
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_cleanup" {
  count = var.deploy_workloads ? 1 : 0

  name     = google_cloud_run_v2_job.task["cleanup"].name
  location = var.region
  role     = "roles/run.invoker"
  member   = google_service_account.scheduler.member
}

resource "google_cloud_scheduler_job" "cleanup" {
  count = var.deploy_workloads ? 1 : 0

  name      = "auth-gateway-cleanup"
  region    = var.region
  schedule  = "0 4 * * *"
  time_zone = "Asia/Tokyo"

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.task["cleanup"].name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.this]
}
