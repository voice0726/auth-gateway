# AGENTS.md

ZITADEL の本人確認を使い、アプリごとに独立した Cookie セッションを提供する Go の認証 gateway です。
本書は、エージェントが作業するときの規則をまとめた要約です。
接続契約・設定項目・運用手順は README.md を正とします。README と内容が食い違うときは README に合わせ、本書を直します。

## 構成

- `cmd/server`: gateway 本体。fx で config・logger・DB・echo を組み立てる
- `cmd/migrate`: `auth` DB の作成と migration。gateway の起動時には実行しない
- `cmd/cleanup`: 期限切れのセッションと login state を削除する
- `internal/server`: ルーティング、`X-App-Id` によるアプリ振り分け、内部トークン照合、レート制限
- `internal/handler/auth`: `/auth/*` と `/internal/session` のハンドラと Cookie 操作
- `internal/service`: 認証フロー、戻り先の検証、セッション管理
- `internal/infra/db`: GORM による PostgreSQL リポジトリ。`app_id` を束縛して生成する
- `internal/infra/zitadel`: アプリ別の OIDC クライアント
- `internal/config`: YAML 設定の読み込みと `applications` の検証
- `infra/`: GCP の Terraform。手順は infra/README.md
- `plans/`: 設計計画。冒頭の「状態」で実装済みかを確かめてから読む
- `kube/`: 旧単一アプリ形式の技術実験。現行コードでは起動しない。変更対象にしない

## 検証

変更後は CI（`.github/workflows/deploy.yml`）と同じ項目を通します。

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
go build ./...
```

`internal/infra/db` の統合テストは `GATEWAY_TEST_DB_PORT` が無いとスキップされます。
スキップされたテストを通過扱いにしないでください。
DB に触れる変更では、使い捨ての PostgreSQL（ユーザー `postgres`、パスワード `test-only`）を用意して実行します。

```sh
docker run -d --rm --name gateway-test-db -e POSTGRES_PASSWORD=test-only -p 127.0.0.1:25432:5432 postgres:17
until docker exec gateway-test-db pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
GATEWAY_TEST_DB_PORT=25432 go test -race ./...; docker stop gateway-test-db
```

テストが失敗してもコンテナを止めます（`;` で続けているため）。`EnsureDatabase` は接続エラーを再試行しないので、`pg_isready` で起動完了を待ってから実行します。

Compose の `db`（15432）は開発データを持つので、統合テストに使わないでください。
Compose を変えたときは `docker compose config --quiet` も通します。

## 認証境界の不変条件

次の性質を崩す変更は、意図した仕様変更であっても README と同じ PR で更新します。

- アプリ間の分離: セッション・login state・Cookie 名・暗号鍵・トークンはすべてアプリ単位。リポジトリは `app_id` で絞らずに行を読まない
- `X-App-Id` はアプリの判別だけに使う。認証情報として扱わない
- `/internal/*` はアプリ専用の `X-Internal-Token` でアプリを特定する。`X-App-Id` を使わない
- `X-Client-Ip` は `X-Proxy-Token` が一致したときだけ信用する
- トークン比較は固定長ダイジェストで行い、一致時点で打ち切らない
- ログイン後の戻り先は同一オリジンの相対パスだけ（`config.IsSafeRelativePath`）
- `/auth/*` と `/internal/*` の応答には `Cache-Control: no-store` を付ける
- 旧形式（単一アプリ設定、`redis_*`、`/auth/<アプリID>/*`）は受け付けない。互換レイヤーを足さない

`internal/server` 配下の `*_test.go` が上記の多くを固定しています。挙動を変えるときはテストを先に直します。

## 設定と秘密情報

`config/dev.yaml` と `config/compose.yaml` の鍵・トークンは開発用の固定値です。
実環境の値をリポジトリに書かないでください。本番設定は Secret Manager にあります。
`login-client.pat` などの PAT はコミットしません。

設定項目を追加したら、`internal/config` の検証、両方の設定例、README の「設定と起動」を揃えます。

## DB スキーマ

テーブルは `internal/model` の struct から、`cmd/migrate` の GORM `AutoMigrate` で作ります。
main への push で本番の migrate Job が新イメージより先に走ります。
そのため、スキーマの変更は旧バージョンの gateway が動き続けられる形にします。

## 実装の方針

- 独自実装より既存ライブラリを使う。例: gorm の logger は zapgorm2、JSONB は pgtype
- repository の新しいメソッドには `Create`・`Get`・`Delete` のような CRUD の名前を付ける
- `Get` などの読み取りに副作用を持たせない。削除を伴う取得は `Consume` のように名前で示す

## 本番デプロイ

main への push で Cloud Run へ自動デプロイされます。
`infra/` の Terraform・`gcloud` で本番リソースを操作するコマンドは、ユーザーの明示指示なしに実行しないでください。

## コミットと PR

コミットメッセージと PR は日本語で書きます。
コミットの件名と PR タイトルは Conventional Commits 形式にします。変更範囲が絞れるときは `docs(readme):` のように scope を付けます。
PR は draft で作ります。
`.github/workflows/pullfrog.yml` は外部 action の生成物です。指示された箇所以外を編集しないでください。
