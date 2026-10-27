// jp-pii-detect は日本特化の個人情報（PII）静的検出器。
// git commit hook / GitHub Actions CI からの利用を想定する。
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/baneido/jp-pii-detector/internal/cli"
)

var version = "dev" // -ldflags "-X main.version=..." で上書き

// resolveVersion は表示するバージョン文字列を決める。
// 優先順位:
//  1. -ldflags "-X main.version=..." での明示指定
//  2. go install module@vX.Y.Z で埋め込まれるモジュールバージョン
//  3. ローカルビルド（go build）時は VCS リビジョンから推定
//  4. いずれも無ければ "dev"
func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	return versionFrom(version, info, ok)
}

// versionFrom は resolveVersion の純粋なロジック部分（テスト用に分離）。
func versionFrom(ldflagsVersion string, info *debug.BuildInfo, ok bool) string {
	// ldflags で明示指定されていれば最優先。
	if ldflagsVersion != "dev" && ldflagsVersion != "" {
		return ldflagsVersion
	}
	if !ok || info == nil {
		return ldflagsVersion
	}
	// go install module@vX.Y.Z でインストールした場合はここに入る。
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	// ローカルビルド: 埋め込まれた VCS 情報からコミットを復元する。
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		return ldflagsVersion + "-" + rev + dirty
	}
	return ldflagsVersion
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, cli.Usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		cli.BundledModelDir = bundledModelDir
		os.Exit(cli.RunScan(os.Args[2:], nil))
	case "rules":
		os.Exit(cli.RunRules(os.Args[2:]))
	case "version", "--version", "-version":
		fmt.Println(resolveVersion())
		if bundleInfo != "" {
			fmt.Println(bundleInfo)
		}
	case "help", "-h", "--help":
		fmt.Print(cli.Usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], cli.Usage)
		os.Exit(2)
	}
}
