package main

import (
	"errors"
	"os"
	"path/filepath"
)

// bundledModelDir は、モデル同梱ビルド（scripts/package-model-bundle.sh）が
// -ldflags "-X main.bundledModelDir=model" で埋め込む既定のモデルディレクトリ。
// 相対パスは実行ファイルのあるディレクトリ（シンボリックリンクは解決する）を基準にする。
// 空（通常のビルド）なら、--model-dir を指定しない限りモデルを使わない。
var bundledModelDir = ""

// bundleInfo は、モデル同梱ビルドで version の 2 行目に表示する同梱物の説明
// （例: "bundle: NagaYu/sumi-ja-pii@daa43a0 + onnxruntime 1.31.0"）。
var bundleInfo = ""

// resolveModelDir は、走査で使うモデルディレクトリを決める。優先順位は
// --no-model（使わない）、--model-dir、モデル同梱ビルドの既定（bundledModelDir）。
// 空文字列を返したときはモデルを使わない。
func resolveModelDir(flagDir string, noModel bool, bundled string, executable func() (string, error)) (string, error) {
	if noModel {
		if flagDir != "" {
			return "", errors.New("--no-model と --model-dir は同時に指定できません")
		}
		return "", nil
	}
	if flagDir != "" {
		return flagDir, nil
	}
	if bundled == "" {
		return "", nil
	}
	if filepath.IsAbs(bundled) {
		return bundled, nil
	}
	exe, err := executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), bundled), nil
}

// osExecutable は os.Executable（テストで差し替えるために変数にしている）。
var osExecutable = os.Executable
