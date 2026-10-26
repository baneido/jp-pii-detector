package jppii

import (
	"github.com/baneido/jp-pii-detector/internal/baseline"
	"github.com/baneido/jp-pii-detector/internal/cli"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// CLI 組み込み用の API（試験的）。jp-pii-detect の scan / rules をそのまま
// 実行し、Hooks で別種の検出の合流・除外・追加の出力形式を足せる。
// Hooks がゼロ値なら出力・終了コードは jp-pii-detect と完全に同じ。

type (
	// Hooks は scan に処理を足す拡張点。
	Hooks = cli.Hooks
	// ScanInfo は Hooks.AfterScan に渡される走査の内容。
	ScanInfo = cli.ScanInfo
	// Renderer は追加の出力形式。
	Renderer = cli.Renderer
	// RawFinding はレポート層がそのまま描画する検出（Kind で種別を付けられる）。
	RawFinding = detect.Finding
	// RuleDef は SARIF の driver.rules に載せるルール定義（ID と Description のみ使う）。
	RuleDef = rule.Rule
	// ConfidenceLevel は検出の信頼度。
	ConfidenceLevel = rule.Confidence
)

// 信頼度。
const (
	ConfidenceLow    = rule.Low
	ConfidenceMedium = rule.Medium
	ConfidenceHigh   = rule.High
)

// Usage は jp-pii-detect の scan / rules の使い方。
const Usage = cli.Usage

// RunScan は jp-pii-detect scan を実行して終了コードを返す（args は "scan" より後ろ）。
func RunScan(args []string, h *Hooks) int { return cli.RunScan(args, h) }

// RunRules は jp-pii-detect rules を実行して終了コードを返す。
func RunRules(args []string) int { return cli.RunRules(args) }

// SetBundledModelDir はモデル同梱ビルドの既定モデルディレクトリを設定する。
func SetBundledModelDir(dir string) { cli.BundledModelDir = dir }

// RawFingerprint は baseline / json 出力と同じ fingerprint を RawFinding から計算する。
// RunScan の Hooks 内で呼べば、パスの正規化（フルスキャンではリポジトリルート相対）も
// json 出力の fingerprint と一致する。
func RawFingerprint(salt string, f RawFinding) string {
	return baseline.FindingFingerprint(salt, f)
}
