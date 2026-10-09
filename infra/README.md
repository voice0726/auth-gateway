# infra

GCP プロジェクト `auth-gateway-511100` の基盤を Terraform で管理する。

## 初回手順

1. state 用バケットを作る(Terraform の管理外)。

   ```sh
   gcloud storage buckets create gs://auth-gateway-511100-tfstate \
     --project auth-gateway-511100 --location asia-northeast1 \
     --uniform-bucket-level-access --public-access-prevention
   gcloud storage buckets update gs://auth-gateway-511100-tfstate --versioning
   ```

2. 基盤と検証用PostgreSQL VMを作る(`deploy_workloads=false`)。既定はFree Tier対象の `us-central1` / `e2-micro` です。Artifact Registryは既存の `asia-northeast1` に維持します。初回はワークロードを作らない値を明示します。

   ```sh
   terraform init
   terraform import google_artifact_registry_repository.gateway \
     projects/auth-gateway-511100/locations/asia-northeast1/repositories/auth-gateway
   terraform apply -var=deploy_workloads=false
   ```

   既存のArtifact RegistryがすでにTerraform stateにある場合、importは不要です。GitHub ActionsのWIFは、`main`上の`.github/workflows/deploy.yml`だけを信頼します。

3. DB VM の起動後、本番の設定 YAML に `db_host`、`db_port: 5432`、`db_sslmode: disable`、`db_password` を設定し、Secret Manager に新しいバージョンを登録する。DB ホストとパスワードは `terraform output -raw db_host` と `terraform output -raw db_password` で確認できます。パスワードは VM 起動時に Secret Manager から取得します。

   ```sh
   gcloud secrets versions add gateway-config --data-file=prod.yaml
   ```

4. PostgreSQL の起動と接続を確認してから、イメージを Artifact Registry に push し、production用の変数ファイルを使ってapplyする。Cloud RunとJobは専用のDirect VPCサブネットを使います。

   ```sh
   terraform apply -var-file=production.tfvars -var image=<image_repository>/auth-gateway:<tag>
   ```

   以降の`plan`と`apply`でも`-var-file=production.tfvars`を指定します。`deploy_workloads`に既定値はないため、変数ファイルを指定しないとTerraformは値の入力を求めます。

## 管理外のもの

- `auth.aknr.dev` の割り当てと DNS(Cloudflare)
- ZITADEL Cloud のテナントとアプリ登録
- GitHub Actions のワークフロー

## 検証用 DB の制約

- PostgreSQL は Compute Engine `e2-micro` と30 GBの標準ディスクで動かします。Free Tierの対象リージョンと月間上限を超えた利用、外部IPv4、通信量には料金が発生します。
- DB はバックアップしません。VMまたはディスクを削除した場合、DBを作り直します。
- TerraformはDB VMの置換・削除を要求するplanを止めます。VMを意図的に作り直す場合は、`prevent_destroy`を一時的に外してplanを確認します。
- DB VMとCloud Runは別サブネットに配置します。ファイアウォールとPostgreSQLはCloud Run専用サブネットからの5432番接続を許可します。同サブネットに接続できるCloud RunサービスとJobsが接続元になります。SSHはIAP経由に限定します。
- `region` を変更するとCloud RunとDBの配置先が変わります。Free Tier対象外のリージョンではVM料金が発生します。
