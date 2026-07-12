package eval

import "github.com/baneido/jp-pii-detector/internal/privatecorpus"

// ProfileSpec は公表・CIゲートする評価プロファイルの識別子と検出設定。
type ProfileSpec struct {
	ID          string
	Description string
	Options     Options
}

// PublishedProfiles は同じF1という名前で設定の異なる値を混ぜないための、
// 公表プロファイルの単一の定義。
var PublishedProfiles = []ProfileSpec{
	{
		ID:          "low",
		Description: "rule capability（min_confidence=low、高再現率ルール無効）",
		Options:     Options{MinConfidence: "low"},
	},
	{
		ID:          "medium",
		Description: "default operational（min_confidence=medium、高再現率ルール無効）",
		Options:     Options{MinConfidence: "medium"},
	},
	{
		ID:          "high-recall",
		Description: "high recall operational（min_confidence=medium、高再現率ルール有効）",
		Options:     Options{MinConfidence: "medium", HighRecall: true},
	},
}

// ProfileEvaluation は1プロファイル分の実測結果。
type ProfileEvaluation struct {
	Spec       ProfileSpec
	Stratified Stratified
}

// EvaluatePublishedProfiles は環境変数で指定されたコーパスを3プロファイルで評価する。
func EvaluatePublishedProfiles() ([]ProfileEvaluation, error) {
	corpus, configured, err := privatecorpus.FromEnv()
	if err != nil {
		return nil, err
	}
	if !configured {
		return nil, ErrNoDataset
	}
	return EvaluatePublishedProfileCases(corpus.Dataset)
}

// EvaluatePublishedProfileCases は指定ケースを3プロファイルで評価する。
func EvaluatePublishedProfileCases(cases []Case) ([]ProfileEvaluation, error) {
	out := make([]ProfileEvaluation, 0, len(PublishedProfiles))
	for _, spec := range PublishedProfiles {
		stratified, err := EvaluateCasesStratifiedWithOptions(cases, spec.Options)
		if err != nil {
			return nil, err
		}
		out = append(out, ProfileEvaluation{Spec: spec, Stratified: stratified})
	}
	return out, nil
}

// FindProfile はIDに対応する評価結果を返す。
func FindProfile(profiles []ProfileEvaluation, id string) (ProfileEvaluation, bool) {
	for _, profile := range profiles {
		if profile.Spec.ID == id {
			return profile, true
		}
	}
	return ProfileEvaluation{}, false
}
