variable "project_id" {
  type    = string
  default = "auth-gateway-511100"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type        = string
  description = "DB VMのゾーン。未指定ならregion-aを使う"
  default     = null
}

variable "artifact_region" {
  description = "既存Artifact Registryを維持するリージョン"
  type        = string
  default     = "asia-northeast1"
}

variable "db_subnet_cidr" {
  type    = string
  default = "10.20.0.0/24"
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

variable "db_machine_type" {
  type    = string
  default = "e2-micro"
}

variable "max_instances" {
  type    = number
  default = 2
}
