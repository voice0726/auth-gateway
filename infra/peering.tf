# shared-infra 側も逆向きの peering を作ったときに ACTIVE になる
resource "google_compute_network_peering" "shared_db" {
  count = var.shared_db_network == null ? 0 : 1

  name         = "auth-gateway-to-shared-db"
  network      = google_compute_network.auth.self_link
  peer_network = "https://www.googleapis.com/compute/v1/${var.shared_db_network}"
}
