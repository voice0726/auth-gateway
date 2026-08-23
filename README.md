# auth-gateway

ZITADEL を使った認証・セッション管理用の Auth Gateway です。フロントは `session_id` Cookie のみを保持し、
認証フローとセッション管理は本サービスが担当します。

## 主要エンドポイント

- `GET /auth/login` : 認証開始 (Authorization Code + PKCE)
- `GET /auth/callback` : 認証コールバック
- `POST /auth/logout` : ログアウト
- `GET /auth/me` : フロント向けのユーザー情報取得
- `GET /internal/session` : BFF 向けのユーザー情報取得

## 設定 (YAML)

`config/dev.yaml` を読み込みます。別のパスを使う場合は `CONFIG_PATH` を指定してください。

### 設定項目

- `env`
- `server_addr`
- `db_host`
- `db_port`
- `db_user`
- `db_password`
- `db_name`
- `db_sslmode`
- `db_timezone`
- `zitadel_issuer`
- `zitadel_client_id`
- `zitadel_client_secret` (PKCE では未使用)
- `zitadel_redirect_uri`
- `zitadel_scopes`
- `zitadel_port`
- `zitadel_insecure` (http 利用時は true)
- `session_secret` (16/24/32 bytes)
- `session_ttl`
- `state_ttl`
- `frontend_post_logout_url`
- `app_host`
- `cookie_name`
- `cookie_secure`
- `cookie_domain`
- `cookie_same_site` (Lax/Strict/None)
- `log_level`
- `log_format` (pretty/json)
- `internal_token`
- `cors_allow_origins`
- `redis_addr`
- `redis_password`
- `redis_db`
- `redis_prefix`

※ `zitadel_issuer` はホスト名のみを指定します（例: `localhost`）。

## 起動

```bash
# config/dev.yaml を編集

go run ./cmd/server
```
