package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveModelDir(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "dist", "jp-pii-detect")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "bin", "jp-pii-detect")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	realDir, err := filepath.EvalSymlinks(filepath.Dir(real))
	if err != nil {
		t.Fatal(err)
	}
	exeAt := func(p string) func() (string, error) { return func() (string, error) { return p, nil } }
	exeErr := func() (string, error) { return "", errors.New("no exe") }

	tests := []struct {
		name    string
		flagDir string
		noModel bool
		bundled string
		exe     func() (string, error)
		want    string
		wantErr bool
	}{
		{name: "通常ビルドで未指定ならモデルを使わない", exe: exeErr, want: ""},
		{name: "--model-dir を優先する", flagDir: "/m", bundled: "model", exe: exeErr, want: "/m"},
		{name: "同梱ビルドは実行ファイル基準で解決する", bundled: "model", exe: exeAt(real), want: filepath.Join(realDir, "model")},
		{name: "シンボリックリンク経由でも実体の隣を見る", bundled: "model", exe: exeAt(link), want: filepath.Join(realDir, "model")},
		{name: "絶対パスの既定はそのまま", bundled: "/opt/sumi", exe: exeErr, want: "/opt/sumi"},
		{name: "--no-model は同梱の既定を無効にする", noModel: true, bundled: "model", exe: exeAt(real), want: ""},
		{name: "--no-model と --model-dir の併用はエラー", noModel: true, flagDir: "/m", exe: exeErr, wantErr: true},
		{name: "実行ファイルの場所が分からなければエラー", bundled: "model", exe: exeErr, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveModelDir(tt.flagDir, tt.noModel, tt.bundled, tt.exe)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
