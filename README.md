# auth-gateway

ZITADELの本人確認を使い、アプリごとに独立したCookieセッションを提供します。gatewayプロセスとPostgreSQLは共有します。

## 責任境界

| 保存先 | 所有者と役割 |
| --- | --- |
| PostgreSQL `zitadel` | ZITADEL。アカウントと本人確認を管理 |
| PostgreSQL `auth` の `sessions` | gateway。`app_id` ごとにセッションを保存・検索・削除 |
| PostgreSQL `auth` の `login_states` | gateway。`app_id` ごとにログイン途中のstateと遷移先を保存。callbackで一度だけ消費 |
| 各アプリの業務DB | 各バックエンド。業務データと操作権限を管理 |

通常のログアウトは対象アプリのセッションとCookieだけを削除します。ZITADELのログイン状態は維持するので、別アプリではパスワードを再入力せず本人確認が完了する場合があります。

## 接続契約

ブラウザはアプリと同じオリジンの `/auth/*` を使います。アプリのリバースプロキシは、パスを変えずに固定の `X-App-Id` ヘッダを付けてgatewayへ転送します。Reactの例：

| 呼び出し元 | 公開パス | gatewayへの転送 |
| --- | --- | --- |
| ブラウザ | `GET /auth/login?redirect=/dashboard` | 同じパス（クエリを維持）＋ `X-App-Id: react-app-playground` |
| ZITADELからの復帰 | `GET /auth/callback` | 同上 |
| ブラウザ | `GET /auth/me` | 同上 |
| ブラウザ | `POST /auth/logout` | 同上 |
| Reactバックエンド | 公開しない | `GET /internal/session` ＋ `X-Internal-Token` |

`X-App-Id` が無い、または未登録のときは400です。プロキシはクライアントが送った `X-App-Id` を上書きしてください。ヘッダはアプリの判別だけに使い、認証情報ではありません。

内部APIはアプリ専用の `X-Internal-Token` と転送されたCookieを要求します。トークンからアプリを特定するため、`X-App-Id` は使いません。`/internal/*` をブラウザへ公開しないでください。`/auth/*` と `/internal/*` の応答には `Cache-Control: no-store` を付けます。

Cookie名は `session_<アプリID>`、Domainなし、Path `/`、HttpOnlyです。アプリごとに暗号鍵を分け、別アプリのCookieを名前だけ変更しても使用できないようにします。OIDCライブラリの一時Cookieも分離するため、アプリには異なるホスト名が必要です。`localhost` のポート違いだけでは分離しません。

ログイン後の遷移先は同一オリジンの相対パスに限定します。POSTログアウトは対象アプリのOriginを検証します。旧 `/auth/<アプリID>/*`、`/internal/<アプリID>/session` のパスは提供しません。

## 設定と起動

通常のローカル運用はComposeを基準とします。
`kube/` は独立した技術実験用です。
Kubernetes設定は旧単一アプリ形式のため、そのままではアプリ別セッション版を起動できません。
今回のアプリ別セッション導入では、Kubernetesの更新・適用を完了条件に含めません。

既定は `config/dev.yaml`、Composeでは `config/compose.yaml` を使用します。`CONFIG_PATH` で変更できます。DB・ZITADELの接続設定は共有し、`applications` に次を登録します。

Dockerイメージには設定ファイルを含めません。Composeはホストの `config/` を読み取り専用でマウントします。Cloud RunではSecret Managerの設定を `CONFIG_PATH` で指定してください。

- `id`: 小文字英数字・ハイフンの一意なアプリID
- `origin`: パスなしのアプリURL。ホスト名はアプリごとに分ける
- `client_id`: ZITADELで登録したアプリ専用のOIDCクライアントID
- `session_secret`: アプリ専用の16/24/32バイトAES鍵
- `internal_token`: アプリ専用の内部API認証情報
- `default_redirect`（省略可）: 戻り先が未指定または不正なときの遷移先。同一オリジンの相対パスのみ。既定は `/dashboard`

`cors_allow_origins` は、ブラウザがgatewayへ直接アクセスする開発構成でだけ設定します。本番はアプリと同一オリジンのプロキシ経由なので空にします（空ならCORSは無効）。

設定例の鍵とトークンは開発用の固定値です。実環境ではアプリごとに別の値を用意し、各バックエンドと一致させます。旧単一アプリ形式の設定は受け付けません。

Reactの開発URLは `http://react.localtest.me:5174`。ZITADELの対象OIDCクライアントにリダイレクトURI `http://react.localtest.me:5174/auth/callback` を登録します。gatewayのポートは `8800`、Reactバックエンドは `18080` です。Viteのプロキシ設定は本番ビルドには含まれないため、本番にも同じ `X-App-Id` 付与を行うリバースプロキシが必要です。

```sh
docker compose up -d db
docker compose --profile tools run --build --rm migrate
docker compose up -d --build gateway login
```

Podman環境では同じ引数を `podman compose` に渡します。ZITADELはgateway/loginの依存サービスとして起動します。OIDCクライアントの登録と実環境の設定は先に済ませてください。

`migrate` は接続先のPostgreSQLに `auth` DBがなければ作成し、セッションテーブルを作成・更新します。通常のgateway起動ではDB作成やmigrationは実行しません。DB作成には実行ユーザーのCREATEDB権限が必要です。

期限切れのセッションとログインstateは自動では消えません。`cleanup` を定期実行（本番は日次）して削除します。`docker compose --profile tools run --rm cleanup` で手動実行できます。

PostgreSQLイメージの初回初期化スクリプトだけでは既存ボリュームに対応できないため、明示的な初期化コマンドを使います（[公式イメージの初期化仕様](https://hub.docker.com/_/postgres)）。ボリュームの削除は不要です。

## 既存環境の移行

1. DBのバックアップを取得し、設定を `applications` 形式に変更する。
2. ZITADELのリダイレクトURIと、アプリのプロキシ・内部API接続先を更新する。
3. `migrate` を実行して `sessions.app_id` を追加する。
4. gatewayとアプリを更新して起動し、再ログインする。

既存行は削除もアプリへの自動割り当てもしません。`app_id` がない旧セッションは新しい認証処理では受け付けないため、再ログインが必要です。旧Cookie `session_id` と旧Redisキーは使用しません。Redisは廃止したので、設定の `redis_*` を削除してください（残っていると起動時に拒否されます）。`migrate` が `login_states` を作成します。切替時に進行中だったログインは失敗するため、再度ログインしてください。ZITADELのユーザー・各アプリの業務データは移行対象ではありません。

現在の設定例はReactのみを登録しています。TanStackの現行コードは独自パスワード認証であり、gatewayへの移行は別途必要です。

## 検証

```sh
go test ./...
go vet ./...
go build ./...
docker compose config --quiet
```

PostgreSQL統合テストには既存環境から分離した検証用インスタンスを使います。PostgreSQLは `postgres` ユーザー、パスワード `test-only` とし、`GATEWAY_TEST_DB_PORT` にlocalhostの公開ポートを設定して `go test ./...` を実行します。テストは検証用PostgreSQL内に一意なDBを作成します。変数未指定時は統合テストをスキップします。

この手順はComposeとローカル開発向けです。既存の `kube/` マニフェストには新しい設定形式をまだ反映していません。Kubernetesへ適用する前に、設定とプロキシを更新する必要があります。
