// Command pii-fixture は、評価データセット Nemotron-PII-Japan（NVIDIA、CC BY 4.0）を
// fixtures.lock.json で固定した revision から取得し、SHA-256 を照合したうえで
// internal/eval が読む評価ケースの JSON（JP_PII_FIXTURES）へ変換する開発補助コマンドである。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/baneido/jp-pii-detector/internal/nemotron"
	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

const lockPath = "fixtures.lock.json"

// baseURL は Hugging Face のダウンロード元。テストで差し替える。
var baseURL = "https://huggingface.co"

type lockFile struct {
	SchemaVersion int    `json:"schema_version"`
	DatasetID     string `json:"dataset_id"`
	Repo          string `json:"repo"`
	Revision      string `json:"revision"`
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	SampleModulus int    `json:"sample_modulus"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "fetch":
		fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
		fs.SetOutput(stderr)
		out := fs.String("out", "", "評価ケース JSON の出力先（既存ファイルは上書きしない）")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *out == "" {
			return usageError()
		}
		return fetch(*out, stdout)
	case "eval":
		fs := flag.NewFlagSet("eval", flag.ContinueOnError)
		fs.SetOutput(stderr)
		update := fs.Bool("update", false, "docs/accuracy.*・README の精度表記を再生成する")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return usageError()
		}
		return runEval(*update, stdout, stderr)
	case "purge":
		if len(args) != 1 {
			return usageError()
		}
		root, err := cacheRoot()
		if err != nil {
			return err
		}
		if err := os.RemoveAll(root); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "fixture cache purged")
		return nil
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: pii-fixture fetch -out PATH | eval [-update] | purge")
}

// fetch は parquet を取得（キャッシュ済みならそれを使い）、評価ケースへ変換して out へ書く。
func fetch(out string, stdout io.Writer) error {
	lock, err := loadLock(lockPath)
	if err != nil {
		return err
	}
	parquetPath, err := cachedParquet(lock, stdout)
	if err != nil {
		return err
	}
	f, err := os.Open(parquetPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	rows, err := nemotron.ReadParquet(f, st.Size())
	if err != nil {
		return err
	}
	cases, err := nemotron.Convert(rows, lock.SampleModulus)
	if err != nil {
		return err
	}
	corpus := &privatecorpus.Corpus{
		SchemaVersion: privatecorpus.CurrentSchemaVersion,
		DatasetID:     lock.DatasetID,
		Dataset:       cases,
	}
	if err := privatecorpus.WriteNew(out, corpus); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s: dataset_id=%s rows=%d cases=%d\n", out, lock.DatasetID, len(rows), len(cases))
	return nil
}

func runEval(update bool, stdout, stderr io.Writer) error {
	dir, err := os.MkdirTemp("", "jp-pii-fixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "corpus.json")
	if err := fetch(path, stdout); err != nil {
		return err
	}
	if update {
		if err := goTest(path, stdout, stderr, "./internal/eval", "-timeout", "60m", "-run", "TestGenerateDoc|TestReadmeBadges", "-update"); err != nil {
			return err
		}
	}
	return goTest(path, stdout, stderr, "./internal/eval", "-timeout", "60m")
}

func loadLock(path string) (lockFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return lockFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	var lock lockFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return lockFile{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if lock.SchemaVersion != 2 || lock.DatasetID == "" || lock.Repo == "" || lock.File == "" ||
		len(lock.Revision) != 40 || len(lock.SHA256) != 64 || lock.SampleModulus < 1 {
		return lockFile{}, fmt.Errorf("%s の必須項目が不正です", path)
	}
	return lock, nil
}

// cachedParquet は、SHA-256 が lock と一致するキャッシュ済み parquet のパスを返す。
// 無ければ取得し、一致を確かめてからキャッシュへ置く。
func cachedParquet(lock lockFile, stdout io.Writer) (string, error) {
	root, err := cacheRoot()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(root, lock.SHA256+".parquet")
	if sum, err := fileSHA256(path); err == nil && sum == lock.SHA256 {
		return path, nil
	}
	url := fmt.Sprintf("%s/datasets/%s/resolve/%s/%s", baseURL, lock.Repo, lock.Revision, lock.File)
	fmt.Fprintf(stdout, "downloading %s\n", url)
	tmp, err := os.CreateTemp(root, "download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := download(url, tmp); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	sum, err := fileSHA256(tmp.Name())
	if err != nil {
		return "", err
	}
	if sum != lock.SHA256 {
		return "", fmt.Errorf("SHA-256 が一致しません: got %s, want %s", sum, lock.SHA256)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

func download(url string, w io.Writer) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func goTest(path string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command("go", append([]string{"test"}, args...)...)
	cmd.Env = append(os.Environ(), privatecorpus.EnvVar+"="+path)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	return nil
}

func cacheRoot() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "jp-pii-detector", "fixtures"), nil
}
