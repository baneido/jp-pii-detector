package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

// TestCommittedLockIsValid は、リポジトリの fixtures.lock.json が読めることを確認する。
func TestCommittedLockIsValid(t *testing.T) {
	if _, err := loadLock(filepath.Join("..", "..", lockPath)); err != nil {
		t.Fatal(err)
	}
}

// TestCachedParquetVerifiesSHA256 は、取得物の SHA-256 が lock と一致するときだけ
// キャッシュへ置き、2 回目はダウンロードしないことを確認する。
func TestCachedParquetVerifiesSHA256(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	body := []byte("parquet-bytes")
	sum := sha256.Sum256(body)
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/datasets/o/r/resolve/"+strings.Repeat("a", 40)+"/data.parquet" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	baseURL = srv.URL
	lock := lockFile{SchemaVersion: 2, DatasetID: "d", Repo: "o/r", Revision: strings.Repeat("a", 40),
		File: "data.parquet", SHA256: hex.EncodeToString(sum[:]), SampleModulus: 1}

	path, err := cachedParquet(lock, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, body) {
		t.Fatalf("cached = %q", got)
	}
	if _, err := cachedParquet(lock, &bytes.Buffer{}); err != nil || requests != 1 {
		t.Fatalf("2 回目: err=%v requests=%d（キャッシュを使っていない）", err, requests)
	}

	lock.SHA256 = strings.Repeat("0", 64)
	if _, err := cachedParquet(lock, &bytes.Buffer{}); err == nil {
		t.Fatal("SHA-256 不一致でエラーにならない")
	}
}
