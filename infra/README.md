# infra

GCP プロジェクト `auth-gateway-511100` の基盤を Terraform で管理する。

DB は、shared-infra リポジトリが管理する共有 DB VM の `auth` データベースを使います。このリポジトリは、Cloud Run 用の VPC と、共有 DB の VPC との peering を持ちます。

## 初回手順

1. state 用バケットを作る(Terraform の管理外)。

   ```sh
   gcloud storage buckets create gs://auth-gateway-511100-tfstate \
     --project auth-gateway-511100 --location asia-northeast1 \
     --uniform-bucket-level-access --public-access-prevention
   gcloud storage buckets update gs://auth-gateway-511100-tfstate --versioning
   ```

2. 基盤を作る(`deploy_workloads=false`)。既定のリージョンは `us-central1` です。Artifact Registryは既存の `asia-northeast1` に維持します。初回はワークロードを作らない値を明示します。

   ```sh
   terraform init
   terraform import google_artifact_registry_repository.gateway \
     projects/auth-gateway-511100/locations/asia-northeast1/repositories/auth-gateway
   terraform apply -var=deploy_workloads=false -var=shared_db_network=<db_network>
   ```

   `<db_network>` は shared-infra の `terraform output -raw db_network` です。peering は、shared-infra 側も逆向きの peering を作ったときに `ACTIVE` になります。

   既存のArtifact RegistryがすでにTerraform stateにある場合、importは不要です。GitHub ActionsのWIFは、`main`上の`.github/workflows/deploy.yml`だけを信頼します。

   `.github/workflows/deploy.yml` はPull RequestでPostgreSQL付きのテストを実行します。mainへのpushではテスト成功後にイメージを公開し、migrate Jobを実行してからCloud Runサービスを更新します。

3. 本番の設定 YAML に `db_host`、`db_port: 5432`、`db_sslmode: require`、`db_password` を設定し、Secret Manager に新しいバージョンを登録する。共有 DB は TLS の接続だけを受け付けます。DB ホストとパスワードは、shared-infra の `terraform output -raw db_host` と `terraform output -json db_passwords` の `auth-gateway` です。

   ```sh
   gcloud secrets versions add gateway-config --data-file=prod.yaml
   ```

4. イメージを Artifact Registry に push し、production用の変数ファイルを使ってapplyする。Cloud RunとJobは専用のDirect VPCサブネットを使います。

   ```sh
   terraform apply -var-file=production.tfvars -var image=<image_repository>/auth-gateway:<tag>
   ```

   以降の`plan`と`apply`でも`-var-file=production.tfvars`を指定します。`deploy_workloads`に既定値はないため、変数ファイルを指定しないとTerraformは値の入力を求めます。

## 設定 YAML の更新

gateway は設定 YAML を起動時に 1 回だけ読みます。そのため、`gateway-config` に新しいバージョンを登録したら、`config-version` の label を付けて新しいリビジョンを作ります。Terraform はこの label の差分を無視します。

```sh
gcloud secrets versions add gateway-config --project auth-gateway-511100 --data-file=prod.yaml
gcloud run services update auth-gateway --project auth-gateway-511100 --region us-central1 \
  --update-labels config-version=<VERSION>
```

migrate Job と cleanup Job は、実行のたびに最新のバージョンを読みます。

## 管理外のもの

- `auth.aknr.dev` の割り当てと DNS(Cloudflare)
- ZITADEL Cloud のテナントとアプリ登録
- GitHub Actions のワークフローファイル。認証先のWIF設定とIAM権限はTerraformで管理します。
- DB VM。shared-infra リポジトリで管理します。

## 制約

- Cloud Run と Job は、専用サブネット(`cloud_run_subnet_cidr`)から Direct VPC egress で共有 DB に接続します。共有 DB の `pg_hba.conf` は、`auth` への接続をこのサブネットからだけ許可します。サブネットの範囲を変えるときは、shared-infra の `production.tfvars` の `client_cidr` も合わせて変えます。
- `region` を変更するとCloud Runの配置先が変わります。共有 DB は `us-central1` にあります。
