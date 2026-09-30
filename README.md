# auth-gateway

ZITADELの本人確認を使い、アプリごとに独立したCookieセッションを提供します。gatewayプロセス・PostgreSQL・Redisは共有します。

## 責任境界

| 保存先 | 所有者と役割 |
| --- | --- |
| PostgreSQL `zitadel` | ZITADEL。アカウントと本人確認を管理 |
| PostgreSQL `auth` の `sessions` | gateway。`app_id` ごとにセッションを保存・検索・削除 |
| Redis | gateway。アプリ別のキープレフィックスでログイン途中のstateと遷移先を保存 |
| 各アプリの業務DB | 各バックエンド。業務データと操作権限を管理 |

通常のログアウトは対象アプリのセッションとCookieだけを削除します。ZITADELのログイン状態は維持するので、別アプリではパスワードを再入力せず本人確認が完了する場合があります。

## 接続契約

ブラウザはアプリと同じオリジンの `/auth/*` を使います。アプリのリバースプロキシは、固定されたアプリIDを付けてgatewayへ転送します。Reactの例：

| 呼び出し元 | 公開パス | gatewayのパス |
| --- | --- | --- |
| ブラウザ | `GET /auth/login?redirect=/dashboard` | `GET /auth/react-app-playground/login`（クエリを維持） |
| ZITADELからの復帰 | `GET /auth/callback` | `GET /auth/react-app-playground/callback` |
| ブラウザ | `GET /auth/me` | `GET /auth/react-app-playground/me` |
| ブラウザ | `POST /auth/logout` | `POST /auth/react-app-playground/logout` |
| Reactバックエンド | 公開しない | `GET /internal/react-app-playground/session` |

内部APIはアプリ専用の `X-Internal-Token` と転送されたCookieを要求します。アプリIDは認証情報ではありません。プロキシでは固定のアプリIDを使い、`/internal/*` をブラウザへ公開しないでください。

Cookie名は `session_<アプリID>`、Domainなし、Path `/`、HttpOnlyです。アプリごとに暗号鍵を分け、別アプリのCookieを名前だけ変更しても使用できないようにします。OIDCライブラリの一時Cookieも分離するため、アプリには異なるホスト名が必要です。`localhost` のポート違いだけでは分離しません。

ログイン後の遷移先は同一オリジンの相対パスに限定します。POSTログアウトは対象アプリのOriginを検証します。旧 `/auth/me`、`/internal/session` などアプリIDを持たないgatewayのパスは提供しません。

## 設定と起動

通常のローカル運用はComposeを基準とします。
`kube/` は独立した技術実験用です。
Kubernetes設定は旧単一アプリ形式のため、そのままではアプリ別セッション版を起動できません。
今回のアプリ別セッション導入では、Kubernetesの更新・適用を完了条件に含めません。

既定は `config/dev.yaml`、Composeでは `config/compose.yaml` を使用します。`CONFIG_PATH` で変更できます。DB・Redis・ZITADELの接続設定は共有し、`applications` に次を登録します。

- `id`: 小文字英数字・ハイフンの一意なアプリID
- `origin`: パスなしのアプリURL。ホスト名はアプリごとに分ける
- `client_id`: ZITADELで登録したアプリ専用のOIDCクライアントID
- `session_secret`: アプリ専用の16/24/32バイトAES鍵
- `internal_token`: アプリ専用の内部API認証情報

設定例の鍵とトークンは開発用の固定値です。実環境ではアプリごとに別の値を用意し、各バックエンドと一致させます。旧単一アプリ形式の設定は受け付けません。

Reactの開発URLは `http://react.localtest.me:5174`。ZITADELの対象OIDCクライアントにリダイレクトURI `http://react.localtest.me:5174/auth/callback` を登録します。gatewayのポートは `8800`、Reactバックエンドは `18080` です。Viteのプロキシ設定は本番ビルドには含まれないため、本番にも同じパス変換を持つリバースプロキシが必要です。

```sh
docker compose up -d db redis
docker compose --profile tools run --build --rm migrate
docker compose up -d --build gateway login
```

Podman環境では同じ引数を `podman compose` に渡します。ZITADELはgateway/loginの依存サービスとして起動します。OIDCクライアントの登録と実環境の設定は先に済ませてください。

`migrate` は接続先のPostgreSQLに `auth` DBがなければ作成し、セッションテーブルを作成・更新します。通常のgateway起動ではDB作成やmigrationは実行しません。DB作成には実行ユーザーのCREATEDB権限が必要です。

PostgreSQLイメージの初回初期化スクリプトだけでは既存ボリュームに対応できないため、明示的な初期化コマンドを使います（[公式イメージの初期化仕様](https://hub.docker.com/_/postgres)）。ボリュームの削除は不要です。

## 既存環境の移行

1. DBのバックアップを取得し、設定を `applications` 形式に変更する。
2. ZITADELのリダイレクトURIと、アプリのプロキシ・内部API接続先を更新する。
3. `migrate` を実行して `sessions.app_id` を追加する。
4. gatewayとアプリを更新して起動し、再ログインする。

既存行は削除もアプリへの自動割り当てもしません。`app_id` がない旧セッションは新しい認証処理では受け付けないため、再ログインが必要です。旧Cookie `session_id` と旧Redisキーは新しい処理では使用しません。ZITADELのユーザー・各アプリの業務データは移行対象ではありません。

現在の設定例はReactのみを登録しています。TanStackの現行コードは独自パスワード認証であり、gatewayへの移行は別途必要です。

## 検証

```sh
go test ./...
go vet ./...
go build ./...
docker compose config --quiet
```

PostgreSQL・Redis統合テストには既存環境から分離した検証用インスタンスを使います。PostgreSQLは `postgres` ユーザー、パスワード `test-only` とし、`GATEWAY_TEST_DB_PORT` と `GATEWAY_TEST_REDIS_PORT` にlocalhostの公開ポートを設定して `go test ./...` を実行します。テストは検証用PostgreSQL内に一意なDBを作成します。変数未指定時は統合テストをスキップします。

この手順はComposeとローカル開発向けです。既存の `kube/` マニフェストには新しい設定形式をまだ反映していません。Kubernetesへ適用する前に、設定とプロキシを更新する必要があります。
