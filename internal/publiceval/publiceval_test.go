package publiceval

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/eval"
)

var update = flag.Bool("update", false, "testdata/golden.json を実測値で再生成する")

const goldenPath = "testdata/golden.json"

// TestPublicSyntheticGate は PR 時の精度ゲート。公開合成コーパスをゲート用
// プロファイルで評価し、ルール × プロファイルごとに再現率の低下・誤検出の増加が
// 許容幅を超えたら失敗する。意図した変化なら -update でゴールデンを再生成して
// 差分をレビューに出す。
func TestPublicSyntheticGate(t *testing.T) {
	cases := Cases()
	got, err := Evaluate(cases)
	if err != nil {
		t.Fatal(err)
	}
	problems := CoverageProblems(cases, got)

	if *update {
		if len(problems) > 0 {
			t.Fatalf("評価ラベルの不整合があるためゴールデンを更新しません:\n%s", strings.Join(problems, "\n"))
		}
		if err := eval.SaveGolden(goldenPath, got); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s を更新しました", goldenPath)
		return
	}

	want, err := eval.LoadGolden(goldenPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s がありません。go test ./internal/publiceval -update で生成してください", goldenPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	rep := Compare(got, want, DefaultTolerance)
	writeSummary(t, Markdown(got, rep, problems))

	for _, p := range problems {
		t.Errorf("評価ラベル: %s", p)
	}
	for _, r := range rep.Regressions {
		t.Errorf("回帰: %s", r)
	}
	if len(rep.Stale) > 0 {
		// 改善や許容内の変化は失敗にしないが、放置すると次の悪化を見逃す
		// 幅が広がるため、GitHub Actions の警告として目立たせる。
		t.Logf("ゴールデンとの差分（悪化ではない）が %d 件あります。go test ./internal/publiceval -update で再生成してください:\n%s",
			len(rep.Stale), strings.Join(rep.Stale, "\n"))
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Logf("::warning title=public-eval::公開合成コーパスのゴールデンが古くなっています（%d 件、悪化ではない）。go test ./internal/publiceval -update で再生成してください", len(rep.Stale))
		}
	}
}

// writeSummary は PUBLIC_EVAL_SUMMARY が指すファイルへ Markdown を追記する
// （CI では $GITHUB_STEP_SUMMARY を渡す）。
func writeSummary(t *testing.T, md string) {
	t.Helper()
	path := os.Getenv("PUBLIC_EVAL_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("サマリを書き込めません: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(md); err != nil {
		t.Errorf("サマリを書き込めません: %v", err)
	}
}

// TestCasesDeterministic は合成コーパスが実行ごとに変わらないこと（ゴールデン
// 比較の前提）を確認する。
func TestCasesDeterministic(t *testing.T) {
	a, b := Cases(), Cases()
	if len(a) != len(b) {
		t.Fatalf("ケース数が実行ごとに変わる: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Line != b[i].Line || a[i].Content != b[i].Content {
			t.Fatalf("ケース %d (%s) が実行ごとに変わる", i, a[i].ID)
		}
	}
}

func goldenWith(rules ...eval.GoldenRule) eval.Golden {
	return eval.Golden{DatasetID: DatasetID, Profiles: []eval.GoldenProfile{{ID: "p", Rules: rules}}}
}

func rule(id string, tp, fp, fn int) eval.GoldenRule {
	r := eval.GoldenRule{RuleID: id}
	r.Row.TP, r.Row.FP, r.Row.FN = tp, fp, fn
	if tp+fn > 0 {
		r.Row.Recall = float64(tp) / float64(tp+fn)
	}
	return r
}

func TestCompare(t *testing.T) {
	tol := Tolerance{RecallDrop: 0.05}
	tests := []struct {
		name             string
		got, want        eval.Golden
		regressions, stl int
	}{
		{"同一", goldenWith(rule("a", 10, 0, 0)), goldenWith(rule("a", 10, 0, 0)), 0, 0},
		{"許容内の再現率低下", goldenWith(rule("a", 99, 0, 1)), goldenWith(rule("a", 100, 0, 0)), 0, 1},
		{"許容超の再現率低下", goldenWith(rule("a", 8, 0, 2)), goldenWith(rule("a", 10, 0, 0)), 1, 0},
		{"誤検出の増加", goldenWith(rule("a", 10, 1, 0)), goldenWith(rule("a", 10, 0, 0)), 1, 0},
		{"改善", goldenWith(rule("a", 10, 0, 0)), goldenWith(rule("a", 9, 1, 1)), 0, 1},
		{"ルールの消失（改名）", goldenWith(rule("b", 10, 0, 0)), goldenWith(rule("a", 10, 0, 0)), 1, 1},
		{"dataset_id 不一致", eval.Golden{DatasetID: "x"}, eval.Golden{DatasetID: DatasetID}, 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := Compare(tt.got, tt.want, tol)
			if len(rep.Regressions) != tt.regressions || len(rep.Stale) != tt.stl {
				t.Errorf("regressions=%v stale=%v, want %d/%d", rep.Regressions, rep.Stale, tt.regressions, tt.stl)
			}
		})
	}
}

// TestCoverageProblemsDetectsUnknownLabel は、ルール改名後に合成器のラベルが
// 旧 ID のまま残ると CoverageProblems が検出することを確認する。
func TestCoverageProblemsDetectsUnknownLabel(t *testing.T) {
	cases := Cases()
	cases[0].Want = []string{"renamed-away-rule"}
	problems := CoverageProblems(cases, eval.Golden{})
	found := false
	for _, p := range problems {
		if strings.Contains(p, "renamed-away-rule") {
			found = true
		}
	}
	if !found {
		t.Fatalf("未知ラベルを検出できない: %v", problems)
	}
}
