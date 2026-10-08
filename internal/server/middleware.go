package server

import "crypto/subtle"

// appByInternalToken は、内部トークンに一致するアプリを返す。
// 一致するまで打ち切らず全アプリと比較する。
func appByInternalToken(apps []appRoutes, token string) (appRoutes, bool) {
	var found appRoutes
	matched := 0
	for _, app := range apps {
		if app.internalToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(app.internalToken)) == 1 {
			found, matched = app, 1
		}
	}
	return found, matched == 1
}
