package main_test

import "runtime"

// exeSuffix はテストでビルドする実行ファイルの拡張子（Windows では .exe がないと
// exec.Command が見つけられない）。
var exeSuffix = func() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}()
