# 注意事項

- gateway, zitadel, login, db, redisの各サービスはnamespace: auth-gatewayで動作します。
- zitadelはStatefulSetで1pod3container構成（zitadel, login, migrate）です。
- gatewayのConfigMapにはcompose.yamlの内容を貼り付けてください。
- PersistentVolumeClaimはdb用のみ作成しています。
- Serviceのtypeは全てClusterIPです（必要に応じてNodePort等に変更してください）。
- 必要に応じてenvやvolumeの細かい調整を行ってください。
- apply順序例はREADME-kube-apply.txtを参照してください。
