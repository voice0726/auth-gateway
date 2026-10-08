package server

import (
	"crypto/sha256"
	"crypto/subtle"
)

// appByInternalToken は、内部トークンに一致するアプリを返す。
// 長さの違いが比較時間に出ないよう、固定長のダイジェストで比較する。
// 一致するまで打ち切らず全アプリと比較する。
func appByInternalToken(apps []appRoutes, token string) (appRoutes, bool) {
	got := sha256.Sum256([]byte(token))
	var found appRoutes
	matched := 0
	for _, app := range apps {
		want := sha256.Sum256([]byte(app.internalToken))
		if app.internalToken != "" && subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			found, matched = app, 1
		}
	}
	return found, matched == 1
}
