// Command pii-fixture は非公開評価コーパスを明示的に取得・検証し、
// private evalだけへ渡す開発補助コマンドである。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

const (
	lockPath         = "fixtures.lock.json"
	bucketEnv        = "JP_PII_FIXTURES_BUCKET"
	projectEnv       = "JP_PII_FIXTURES_PROJECT"
	gcloudAccountEnv = "JP_PII_FIXTURES_GCLOUD_ACCOUNT"
)

type lockFile struct {
	SchemaVersion int    `json:"schema_version"`
	DatasetID     string `json:"dataset_id"`
	Object        string `json:"object"`
	Generation    string `json:"generation"`
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
	case "eval":
		fs := flag.NewFlagSet("eval", flag.ContinueOnError)
		fs.SetOutput(stderr)
		cache := fs.Bool("cache", false, "検証済みコーパスをユーザーキャッシュへ保存する")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return usageError()
		}
		return runEval(*cache, stdout, stderr)
	case "status":
		if len(args) != 1 {
			return usageError()
		}
		return status(stdout)
	case "purge":
		if len(args) != 1 {
			return usageError()
		}
		return purge(stdout)
	case "migrate":
		fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		input := fs.String("input", "", "旧コーパスのローカルパス")
		output := fs.String("output", "", "新コーパスの出力先（既存ファイルは上書きしない）")
		datasetID := fs.String("dataset-id", "", "新コーパスの安定ID")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *input == "" || *output == "" || *datasetID == "" {
			return usageError()
		}
		return migrate(*input, *output, *datasetID, stdout)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: pii-fixture eval [-cache] | status | purge | migrate -input PATH -output PATH -dataset-id ID")
}

func migrate(input, output, datasetID string, stdout io.Writer) error {
	legacy, err := privatecorpus.Load(input)
	if err != nil {
		return err
	}
	corpus, err := privatecorpus.MigrateLegacy(legacy, datasetID, "legacy-curated")
	if err != nil {
		return err
	}
	if err := privatecorpus.WriteNew(output, corpus); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "migrated private corpus: dataset_id=%s cases=%d source_class=legacy-curated\n",
		corpus.DatasetID, len(corpus.Dataset))
	return nil
}

func runEval(cache bool, stdout, stderr io.Writer) error {
	if path := strings.TrimSpace(os.Getenv(privatecorpus.EnvVar)); path != "" {
		if _, err := privatecorpus.Load(path); err != nil {
			return err
		}
		return goTest(path, stdout, stderr)
	}
	lock, err := loadLock()
	if err != nil {
		return err
	}

	path, cleanup, err := corpusPath(lock, cache)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := download(lock, path, stdout, stderr); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	corpus, err := privatecorpus.Load(path)
	if err != nil {
		return err
	}
	if corpus.DatasetID != lock.DatasetID {
		return fmt.Errorf("dataset_id mismatch: lock=%q corpus=%q", lock.DatasetID, corpus.DatasetID)
	}
	return goTest(path, stdout, stderr)
}

func loadLock() (lockFile, error) {
	b, err := os.ReadFile(lockPath)
	if err != nil {
		return lockFile{}, fmt.Errorf("read %s: %w", lockPath, err)
	}
	var lock lockFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return lockFile{}, fmt.Errorf("decode %s: %w", lockPath, err)
	}
	if lock.SchemaVersion != 1 || lock.DatasetID == "" || lock.Object == "" {
		return lockFile{}, fmt.Errorf("%s の必須項目が不正です", lockPath)
	}
	return lock, nil
}

func corpusPath(lock lockFile, cache bool) (string, func(), error) {
	if cache {
		root, err := cacheRoot()
		if err != nil {
			return "", func() {}, err
		}
		dir := filepath.Join(root, lock.DatasetID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", func() {}, err
		}
		return filepath.Join(dir, "pii-fixtures.json"), func() {}, nil
	}
	dir, err := os.MkdirTemp("", "jp-pii-fixture-")
	if err != nil {
		return "", func() {}, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, err
	}
	return filepath.Join(dir, "pii-fixtures.json"), func() { _ = os.RemoveAll(dir) }, nil
}

func download(lock lockFile, path string, stdout, stderr io.Writer) error {
	bucket := strings.TrimSpace(os.Getenv(bucketEnv))
	if bucket == "" {
		return fmt.Errorf("%s を設定してください", bucketEnv)
	}
	source := fmt.Sprintf("gs://%s/%s", bucket, strings.TrimPrefix(lock.Object, "/"))
	if lock.Generation != "" {
		source += "#" + lock.Generation
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	cmd := exec.Command("gcloud", gcloudCopyArgs(source, tmp)...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("gcloud storage cp: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	corpus, err := privatecorpus.Load(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if corpus.DatasetID != lock.DatasetID {
		_ = os.Remove(tmp)
		return fmt.Errorf("dataset_id mismatch: lock=%q corpus=%q", lock.DatasetID, corpus.DatasetID)
	}
	return os.Rename(tmp, path)
}

func gcloudCopyArgs(source, destination string) []string {
	args := []string{"storage", "cp", source, destination, "--quiet"}
	if account := strings.TrimSpace(os.Getenv(gcloudAccountEnv)); account != "" {
		args = append(args, "--account="+account)
	}
	if project := strings.TrimSpace(os.Getenv(projectEnv)); project != "" {
		args = append(args, "--project="+project)
	}
	return args
}

func goTest(path string, stdout, stderr io.Writer) error {
	cmd := exec.Command("go", "test", "./internal/eval")
	cmd.Env = append(os.Environ(), privatecorpus.EnvVar+"="+path)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("private eval: %w", err)
	}
	return nil
}

func status(stdout io.Writer) error {
	lock, err := loadLock()
	if err != nil {
		return err
	}
	root, err := cacheRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, lock.DatasetID, "pii-fixtures.json")
	state := "not cached"
	if _, err := os.Stat(path); err == nil {
		state = "cached"
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(stdout, "dataset_id: %s\ngeneration: %s\ncache: %s\n", lock.DatasetID, lock.Generation, state)
	return nil
}

func purge(stdout io.Writer) error {
	root, err := cacheRoot()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "private fixture cache purged")
	return nil
}

func cacheRoot() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "jp-pii-detector", "fixtures"), nil
}
