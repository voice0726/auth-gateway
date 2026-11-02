variable "project_id" {
  type    = string
  default = "auth-gateway-511100"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "artifact_region" {
  description = "既存Artifact Registryを維持するリージョン"
  type        = string
  default     = "asia-northeast1"
}

variable "cloud_run_subnet_cidr" {
  description = "専用Direct VPC egressサブネット。Cloud Runには/26以上の範囲が必要"
  type        = string
  default     = "10.21.0.0/26"
}

variable "github_repository" {
  type    = string
  default = "voice0726/auth-gateway"
}

variable "image" {
  description = "gateway と各 Job に使うイメージ。CI が更新するため、以降の差分は無視する"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "deploy_workloads" {
  description = "gateway-config の secret version を登録した後に true にする"
  type        = bool
}

variable "max_instances" {
  type    = number
  default = 2
}

variable "shared_db_network" {
  description = "shared-infra の DB 用 VPC（projects/<id>/global/networks/<name>）。null なら peering を作らない"
  type        = string
  default     = null

  validation {
    condition     = var.shared_db_network == null || can(regex("^projects/[a-z][a-z0-9-]+/global/networks/[a-z][a-z0-9-]*$", var.shared_db_network))
    error_message = "shared_db_network は projects/<id>/global/networks/<name> の形式にしてください。"
  }
}
