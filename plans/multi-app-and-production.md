# auth-gateway: マルチアプリ対応の残作業と本番化の計画

状態: フェーズ 1 の項目 0〜4 は #2(`feat/app-id-header`)、項目 5(Redis 廃止)と削除ジョブは #3(`feat/login-state-postgres`)で実装済みです。
フェーズ 2(本番化)は未着手で、本書の設計が正です。以降の「残作業」は、実装前の計画時点の記述です。

## 結論

フェーズ 1(マルチアプリ対応)の本体は、`origin/main` の 8530b16「アプリ別セッションと認証境界を導入 (#1)」で実装済みです。
残るのは、アプリ別の戻り先設定と、本番運用に向けた小さな改修です。
フェーズ 2(本番化)は、デプロイ設定・CI・シークレット注入・DB の置き場がすべて未整備です。Redis は廃止します(決定済み、フェーズ 1 の項目 5)。

依頼文の「`main` は単一アプリ専用」は古い情報です。
元の checkout `~/ghq/github.com/voice0726/auth-gateway` の HEAD が 55f87d5(#1 より前)で止まっているためです。
その checkout の未コミット差分は、旧単一アプリ形式のキー(`zitadel_client_id`)への変更と compose の整形、`login-client.pat` の更新です。
現行の `applications` 形式には適用できません。計画の入力としては使いません。

## 現状(`origin/main` 8530b16)

react-app-playground の README が前提にする要件は、次のとおり満たされています。

| 要件 | 状態 | 場所 |
|---|---|---|
| アプリ別のクライアント ID・Origin・内部トークン・暗号鍵 | 済 | `internal/config/application.go` |
| `/auth/<app>/{login,callback,logout,me}`、`/internal/<app>/session` | 済 | `internal/server/server.go` |
| Cookie 名 `session_<app>`、Domain なし | 済 | `ForApplication` |
| `sessions.app_id` による分離、Redis キーの app プレフィックス | 済 | `session_repository.go`, `state_store.go` |
| 戻り先は同一オリジンの相対パスのみ | 済 | `internal/service/redirect.go` |
| ログアウトの Origin 検証 | 済 | `logoutOrigin` |

README の未決事項「Cookie ドメイン」は解決済みです。アプリ別ホスト・Domain なしで確定します。

## フェーズ 1: 残作業

API 契約の変更(項目 0)と state 保存先の変更(項目 5)を含むため、PR は 2 本に分けます。PR A は項目 0〜4、PR B は項目 5 です。

0. **アプリの判別をパスからヘッダへ変更**(決定済み)。公開 API は `/auth/{login,callback,logout,me}` と `/internal/session` になり、アプリは `X-App-Id` ヘッダで判別します。
   - ミドルウェアが `X-App-Id` から登録済みアプリを引きます。ヘッダ無し・未登録は 400 を返します。旧パス `/auth/<アプリID>/*` と `/internal/<アプリID>/session` は提供しません(旧形式の互換を持たない方針は #1 と同じ)。
   - `/internal/session` は `X-App-Id` を使いません。`X-Internal-Token` からアプリを特定します(トークンはアプリごとに固有)。登録済みトークンのどれにも一致しなければ 401 です。比較は定数時間で行います。
   - Origin 検証・Cookie 名・暗号鍵・state/セッションの保存キー・`app_id` による分離は、解決したアプリ設定で従来どおり動かします。
   - 変更範囲: `server.go` のルーティング、ハンドラへのアプリ設定の渡し方(現状は起動時にアプリごとのハンドラを作っている)、テスト、README の接続契約。
   - 影響: react-app-playground の README、Vite のプロキシ設定(パス書き換えをやめ、ヘッダを付ける)、**バックエンドのセッション照会 URL**(`/internal/react-app-playground/session` → `/internal/session`)の更新が必要です。バックエンドの実際の呼び出し箇所は未確認です。
   - 切替: 旧形式は残さないため、gateway・Workers プロキシ・バックエンドを同時に切り替えます(互換期間なし)。切替時の進行中ログインは失敗し、再ログインが必要です。
   - 認証応答(`/auth/*`、`/internal/*`)に `Cache-Control: no-store` を付けます。
1. **戻り先のアプリ別設定**。`LoginRedirectFallback = "/dashboard"` が全アプリ共通の定数です。`applications[].default_redirect`(省略時 `/dashboard`)を追加し、`SafeRedirect` の fallback に渡します。設定ロード時に `default_redirect` を検証します(`SafeRedirect` は fallback を無検証で返すため)。相対パスのみ許可し、外部 URL・`//host`・バックスラッシュ・制御文字は起動時エラーにします。省略は既定値、不正値は拒否と区別します。`StartLogin` と `HandleCallback` の両方で使う値を差し替えます。react-app-playground は tickets を統合するため、戻り先は `/tickets` 等になり得ます。
2. **内部トークン比較の定数時間化**。`middleware.go` の `token != cfg.InternalToken` を `subtle.ConstantTimeCompare` に変えます。
3. **CORS の整理**。`cors_allow_origins` は `applications[].origin` と別管理です。本番は同一オリジンのプロキシ経由なので CORS 不要です。空なら無効になる現行動作を保ち、本番設定では空にします。コード変更は不要で、設定の指針だけ README に書きます。
4. **2 アプリ同時登録のテスト確認**。`application_test.go` が 2 アプリの Cookie・セッション分離を検証済みか確認し、足りなければ追加します。
5. **Redis の廃止**(決定済み)。ログイン state を PostgreSQL の `login_states` テーブル(`app_id`, `state`, `redirect`, `expires_at`)に移します。
   - `LoginStateService` は interface なので、`internal/infra/db` に実装を足して差し替えます。現行 interface は `Set/Get/Delete` で、callback は Get の後の Delete のエラーを無視しています。これを単一操作 `Consume(state)`(`DELETE ... WHERE app_id = ? AND state = ? RETURNING`)に変え、`service/auth.go` の呼び出しも更新します。期限切れ(`expires_at` 超過)は `ErrStateExpired`、行なしは `ErrStateNotFound` を返します。
   - `login_states` は `(app_id, state)` を主キーにします。DB 障害時はセッションを作りません。
   - テスト: 別アプリの同じ state、期限切れ、並行した二重 callback。
   - 切替時、Redis で開始済みのログインは state が見つからず失敗します(再ログインで復旧)。
   - `internal/infra/redis/`、`redis_*` 設定、go-redis 依存、compose の `redis` サービスを削除します。`kube/` は旧形式のままで対象外です。
   - `migrate` に `login_states` を追加します。期限切れ行は、セッション削除の日次ジョブ(フェーズ 2 の項目 2)で一緒に消します。
   - 設定から `redis_*` を消すと旧設定ファイルは `KnownFields(true)` で読めなくなります。README の「既存環境の移行」に追記します。

react-app-playground が tickets を取り込むため、新しいアプリ登録は発生しません。
`tanstack-playground` のアプリ ID は作りません。

## フェーズ 2: 本番化の設計

### 全体構成

```
ブラウザ → <sub>.aknr.dev (Cloudflare Workers)
             ├ /auth/*  → gateway (Cloud Run) の /auth/*(X-App-Id: react-app-playground を付与)
             ├ /api/*   → react バックエンド (Cloud Run)
             └ その他   → 静的アセット
react バックエンド → gateway /internal/session (X-Internal-Token + 転送 Cookie。アプリはトークンで特定)
gateway → ZITADEL Cloud (OIDC) / Cloud SQL (auth DB。セッションとログイン state を保存)
```

README 未決事項の回答案を次に示します。

- `/api`・`/auth` の到達経路: **Workers でのプロキシ**。gateway は「アプリと同一オリジンの `/auth`」を契約としており、別オリジン+CORS では Cookie が第三者扱いになります。
- Cookie ドメイン: アプリ別ホスト・Domain なし(上記)。
- サブドメイン名: アプリ側 `react-app-playground.aknr.dev`、gateway 側 `auth.aknr.dev`(決定済み)。

### Workers プロキシの要件

- `/auth/*` をパスそのままで gateway へ転送し、固定の `X-App-Id` を付けます。クエリ(`redirect`)と `Cookie`/`Set-Cookie` を維持します。クライアントが送ってきた `X-App-Id` は上書きします。
- 302 を追従せずそのまま返します(`redirect: "manual"`)。
- `/internal/*` は絶対に中継しません。
- アプリ ID はクライアントから受け取らず、Workers 側で固定します。
- 保持する条件(受入条件): HTTP メソッド、全クエリ(`code`/`state`/`error` を含む)、`Origin`(欠けるとログアウトが 403 になる)、複数の `Set-Cookie`(1 本にまとめない。OIDC の一時 Cookie の保存・削除が壊れる)。
- 本番の `cookie_same_site` は `Lax` を維持します(ZITADEL からの復帰に必要。一時 Cookie も同じ設定)。
- `/auth/*`、`/internal/*` の応答は共有キャッシュさせません。
- ブラウザ経由で確認する項目: ログインの 302、callback での一時 Cookie 削除とセッション発行、ログアウトでの Cookie 削除。

### ZITADEL Cloud(Free)

- 設定: プロジェクト作成 → Web アプリ(PKCE、認証方式 none)→ リダイレクト URI `https://<host>/auth/callback`、ログアウト後 URI を登録します。
- gateway 設定: `zitadel_issuer` に `<instance>.zitadel.cloud`、`zitadel_insecure: false`、`zitadel_port: 443`、`cookie_secure: true`。
- Free プランは公式料金ページで 100 DAU・管理者 1 名です([料金ページ](https://www.zitadel.com/pricing))。カスタムドメインは Pro 以上の項目で、Free では使えない前提で設計します。issuer は `*.zitadel.cloud` のままになります。
- ロール claim を `/auth/me` に載せるには、プロジェクト側でロールの付与と ID トークンへの出力設定が必要です。`extractRoles` は `urn:zitadel:iam:org:project:roles` を読みます。
- **未確認**: 「100 DAU」が日次上限か月合計かは、サードパーティの記述が割れています。想定ユーザー数が少なければ影響しません。

### GCP

| 要素 | 案 | 備考 |
|---|---|---|
| gateway | Cloud Run(`min-instances=0`) | 公開 ingress(Workers から到達するため)。起動時に ZITADEL の discovery を呼ぶので、コールドスタートに数百 ms 加わる |
| 設定とシークレット | Secret Manager の YAML 1 ファイルをボリュームマウントし `CONFIG_PATH` で指す | コード変更なし。DB パスワード・鍵・内部トークンを含む |
| PostgreSQL | Cloud SQL `db-f1-micro` 級 | 接続は Unix ソケット(`db_host: /cloudsql/<conn>`)。pgx は対応済みで、`db_port` と `db_sslmode: disable` は形式上必要 |
| migrate | Cloud Run Job(同一イメージ、entrypoint `/app/migrate`) | デプロイごとに gateway の前に実行 |
| 起動条件 | 本番 YAML の `server_addr` を Cloud Run のコンテナポートに合わせる | 現行サーバーは `PORT` 環境変数を読まない |
| 権限 | 実行サービスアカウントに Cloud SQL Client と Secret Manager の読み取り | サービスと migrate Job の両方に Cloud SQL 接続の設定が必要(`/cloudsql/...` を指定するだけではソケットは作られない) |
| イメージ | Artifact Registry | |

**費用の目安(いずれも未確認、Tokyo リージョンの確定値は取れていません)**:

- Redis(Memorystore)は廃止するため費用は発生しません。参考として、Memorystore に永続的な無料枠は見つかりませんでした(1GiB Basic で月 US$36 前後、未確認)。
- Cloud SQL `db-f1-micro` は、近隣リージョンで月 US$10 前後+ストレージです([参考](https://www.bytebase.com/dbcost/cloudsql/instance/db-f1-micro.md))。
- 接続プールの上限(現行 `NewConn` は未設定)と Cloud Run の最大インスタンス数を合わせて決めます。DB の作成は IaC で行うか migrate に作成権限を与えるかも決めます。
- 見積もりは GCP の料金計算ツールで asia-northeast1 を選んで確定させます。

### 必要なコード変更(フェーズ 2)

1. Dockerfile: `ENV CONFIG_PATH=/app/config/dev.yaml` と `COPY config` を外し、開発用の鍵をイメージに焼かないようにします。
2. セッションの期限切れ削除。現状は期限切れ行を削除する処理がなく、`sessions` が増え続けます。Cloud Run Job + Cloud Scheduler で日次削除します。
3. ヘルスチェック `GET /healthz`(DB へ ping しない軽量版)。
4. (欠番。Redis 廃止により `redis_tls` は不要)
5. トークン保存の見直し。`sessions` は access/refresh/ID トークンを平文で保存しますが、refresh token はどこでも使っていません。保存をやめれば漏洩時の被害が減ります。
6. GitHub Actions(`.github/` が無い): `go vet`/`go test`(PostgreSQL を service container で起動し、`GATEWAY_TEST_DB_PORT` とテスト用パスワード `test-only` を設定する。未設定だと統合テストは Skip される)→ イメージ build/push → migrate Job → Cloud Run deploy。認証は Workload Identity Federation。

### `/internal` の公開範囲

Workers が到達するため gateway は公開 ingress になり、`/internal/session` も公開 URL に届きます。ネットワーク上の防御はアプリ別トークンのみです(32 バイト以上の乱数、定数時間比較)。セッション情報を得るには、トークンに加えて、対象アプリの有効な Cookie も必要です。
さらに絞るには、公開サービス(`/auth` のみ)と内部サービス(`/internal` のみ、IAM 認証)にイメージを 2 分割します。
運用コストが増えるため、まずはトークンのみで始めます。

## 判断が必要な点

1. **サブドメイン名**(決定済み)。アプリのホストは `react-app-playground.aknr.dev`(アプリ名と同じ)です。gateway の Cloud Run には `auth.aknr.dev` を割り当て、Workers の転送先にします。アプリごとにホストを分ける必要があるため、将来のアプリは別名になります。ブラウザ側もゲートウェイ側も `/auth/*` で、アプリは `X-App-Id` ヘッダで判別します。
2. **IaC の手段**。推奨は Terraform(`infra/`)で Cloud Run・Cloud SQL・Secret Manager・Artifact Registry を管理することです。代替は `gcloud` の手順書のみです。
3. **GCP プロジェクト**(README 未決事項)。新規の専用プロジェクトを推奨します。既存プロジェクトの有無は私からは分かりません。

## 実施順

1. PR A: ヘッダ判別への変更・戻り先設定(検証つき)・定数時間比較・`no-store`・テスト(フェーズ 1 の項目 0〜4)
2. PR B: Redis 廃止と state の PostgreSQL 化(項目 5)
3. Dockerfile 修正・`/healthz`・セッション削除・`PORT` 対応
4. CI(テストと build。DB 統合テストの環境変数を含む)
5. GCP 基盤(判断 2・3 の結果に従う)と ZITADEL Cloud の設定
6. 初回デプロイと、Workers プロキシ経由の疎通確認(フェーズ 5 で react-app-playground と合流。バックエンドの照会 URL 更新を同時に行う)

## 未確認事項

- `go test ./...` はこの環境のサンドボックスで依存取得できず、`internal/config` の通過のみ確認しました。PostgreSQL を使う統合テストは未実行です。
- Memorystore・Cloud SQL の Tokyo 価格、ZITADEL Free の 100 DAU の定義。
- `application_test.go` の 2 アプリ分離カバレッジ(フェーズ 1 の項目 4)は、本文を精読していません。
- kube/ マニフェストは旧形式のままで、本計画の対象外です(README に明記済み)。
