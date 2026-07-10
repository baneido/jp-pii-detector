// Package baseline は「ベースライン方式」（gitleaks の --baseline-path、
// detect-secrets の .secrets.baseline と同様の運用）を提供する。導入時点で
// 既に混入している検出を凍結し、以降のスキャンでは新規に追加された検出のみを
// fail させたい場合に使う。
//
// Finding そのものではなく、salt 付き HMAC-SHA256 の fingerprint（ルール ID・
// ファイルパス・検出値から算出）だけをベースラインファイルに記録する。行番号は
// 含めないため、同一ファイル内で行が前後に動いても fingerprint は変わらない一方、
// 検出値が 1 文字でも変われば別の fingerprint になり再度検出される。
//
// セキュリティ上の限界: salt は複数リポジトリ間でのレインボーテーブル使い回しを
// 防ぐためのものであり、baseline ファイル自体を入手した攻撃者による低エントロピー
// な値（7 桁の口座番号など）への総当たり照合を防ぐものではない。baseline ファイルは
// 元のソース履歴と同程度の機密度で扱うこと。
package baseline

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/baneido/jp-pii-detector/internal/detect"
)

// CurrentVersion はベースラインファイルの JSON スキーマバージョン。将来
// フォーマットを変更する場合はこの値を上げ、Load 側で互換性を判定する。
const CurrentVersion = 1

// Entry はベースラインに記録された 1 件の検出の fingerprint。
type Entry struct {
	Fingerprint string `json:"fingerprint"`
}

// File はベースラインファイルの JSON スキーマ。
type File struct {
	Version int     `json:"version"`
	Salt    string  `json:"salt"`
	Entries []Entry `json:"entries"`
}

// Fingerprint は (ruleID, file, match) から安定な識別子を計算する。
// 単純な文字列連結のハッシュより衝突耐性の高い HMAC-SHA256 を、リポジトリ
// ごとの salt をキーとして用いる。file は filepath.ToSlash 済みのスラッシュ
// 区切りパス、match は正規化後の生値（detect.Finding.Match）を想定する。
func Fingerprint(salt, ruleID, file, match string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(ruleID))
	mac.Write([]byte{0})
	mac.Write([]byte(file))
	mac.Write([]byte{0})
	mac.Write([]byte(match))
	return hex.EncodeToString(mac.Sum(nil))
}

// FindingFingerprint は detect.Finding から Fingerprint を計算する。
func FindingFingerprint(salt string, f detect.Finding) string {
	return Fingerprint(salt, f.RuleID, f.File, f.Match)
}

// NewSalt はランダムな 16 バイトの salt を生成し、16 進文字列で返す。
func NewSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("baseline: generate salt: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Load はベースラインファイルを読み込む。ファイルが存在しない場合は
// errors.Is(err, os.ErrNotExist) で判定できるエラーを返す（--update-baseline
// の初回作成で「まだ無い」を区別するため）。
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: read %s: %w", path, err)
	}
	var bf File
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	if bf.Version != CurrentVersion {
		return nil, fmt.Errorf("baseline: %s: unsupported version %d (want %d)", path, bf.Version, CurrentVersion)
	}
	if bf.Salt == "" {
		return nil, fmt.Errorf("baseline: %s: missing salt", path)
	}
	return &bf, nil
}

// IsNotExist はベースラインファイルが存在しないことを示すエラーかどうかを返す。
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// Save はベースラインファイルをインデント付き JSON（末尾改行あり）で書き込む。
func Save(path string, bf *File) error {
	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("baseline: write %s: %w", path, err)
	}
	return nil
}

// FromFindings は findings から新規ベースラインを構築する。salt が空なら
// NewSalt で新規生成する。
func FromFindings(findings []detect.Finding, salt string) (*File, error) {
	if salt == "" {
		var err error
		salt, err = NewSalt()
		if err != nil {
			return nil, err
		}
	}
	bf := &File{Version: CurrentVersion, Salt: salt}
	Merge(bf, findings)
	return bf, nil
}

// Merge は既存のベースラインに findings の fingerprint を（重複を除いて）
// 追記する。bf.Salt をそのまま使うため、salt は変わらない。
func Merge(bf *File, findings []detect.Finding) {
	known := make(map[string]bool, len(bf.Entries))
	for _, e := range bf.Entries {
		known[e.Fingerprint] = true
	}
	for _, f := range findings {
		fp := FindingFingerprint(bf.Salt, f)
		if known[fp] {
			continue
		}
		known[fp] = true
		bf.Entries = append(bf.Entries, Entry{Fingerprint: fp})
	}
}

// Filter は findings を、bf に記録済みの fingerprint を持つかどうかで
// kept（新規・未記録）と baselined（記録済み）に分割する。それぞれ入力の
// 順序を保つ。bf が nil の場合は全件 kept とする。
//
// 呼び出しタイミングについて: internal/source の並列スキャンは findings の
// 収集までで完了しており、Filter は収集後の単一 goroutine の後処理として
// 呼ぶ（ゴルーチン間で共有する状態を持たないため、-race との組み合わせで
// 追加のデータレース懸念はない）。
func Filter(findings []detect.Finding, bf *File) (kept, baselined []detect.Finding) {
	if bf == nil {
		return findings, nil
	}
	known := make(map[string]bool, len(bf.Entries))
	for _, e := range bf.Entries {
		known[e.Fingerprint] = true
	}
	for _, f := range findings {
		if known[FindingFingerprint(bf.Salt, f)] {
			baselined = append(baselined, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, baselined
}
