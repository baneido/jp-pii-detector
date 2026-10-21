//go:build !(linux && amd64)

package model

// disableAMX は Linux の x86-64 以外では何もしない（AMX の問題は Linux の
// x86-64 の仮想マシンでだけ確認している。amx_linux_amd64.go を参照）。
func disableAMX() error { return nil }
