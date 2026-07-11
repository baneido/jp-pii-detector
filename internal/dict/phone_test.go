package dict

import "testing"

// ValidAreaCode は埋め込み済みの area_codes.txt（現状は代表的な市外局番のみの
// シードデータ）に対して、先頭から最長一致する市外局番の実在を判定する。
func TestValidAreaCode(t *testing.T) {
	tests := []struct {
		digits  string
		wantLen int
		wantOK  bool
	}{
		{"0312345678", 2, true}, // 03（東京）+ 8 桁
		{"0612345678", 2, true}, // 06（大阪）+ 8 桁
		{"0112345678", 3, true}, // 011（札幌）+ 7 桁
		{"0521234567", 3, true}, // 052（名古屋）+ 7 桁
		// 収録されていないプレフィックス（このシードデータには存在しない）。
		{"0212345678", 0, false},
		{"0000000000", 0, false},
		{"01", 0, false}, // 桁不足
		{"", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.digits, func(t *testing.T) {
			gotLen, gotOK := ValidAreaCode(tt.digits)
			if gotOK != tt.wantOK || (gotOK && gotLen != tt.wantLen) {
				t.Errorf("ValidAreaCode(%q) = (%d, %v), want (%d, %v)", tt.digits, gotLen, gotOK, tt.wantLen, tt.wantOK)
			}
		})
	}
}

// 埋め込みデータが空でロードされていないこと（gen の出力形式が壊れて
// 全件ロード失敗するような回帰を検知する）。件数はシードデータの縮小・拡大を
// 妨げないよう、ゆるい下限のみを確認する。
func TestEmbeddedAreaCodesLoaded(t *testing.T) {
	if len(areaCodes) < 10 {
		t.Fatalf("area_codes.txt から %d 件しか読み込めていません（gen の出力を確認してください）", len(areaCodes))
	}
}

// 最長一致ロジックを、埋め込みデータから独立した手作りの符号集合で検証する
// （実データの収録状況に依存せず、桁数体系だけを確認するテスト）。
func TestMatchAreaCodeLongestMatch(t *testing.T) {
	codes := map[string]bool{"03": true, "045": true, "0466": true, "04996": true}
	tests := []struct {
		digits  string
		wantLen int
		wantOK  bool
	}{
		{"0312345678", 2, true},  // 2 桁一致（03）
		{"0451234567", 3, true},  // 3 桁一致（045）。"03" とも "04" とも一致しない
		{"0466123456", 4, true},  // 4 桁一致（0466）
		{"0499612345", 5, true},  // 5 桁一致（04996）
		{"0499912345", 0, false}, // どの符号にも一致しない
		{"04", 0, false},         // 桁不足
	}
	for _, tt := range tests {
		t.Run(tt.digits, func(t *testing.T) {
			gotLen, gotOK := matchAreaCode(codes, 2, 5, tt.digits)
			if gotOK != tt.wantOK || (gotOK && gotLen != tt.wantLen) {
				t.Errorf("matchAreaCode(%q) = (%d, %v), want (%d, %v)", tt.digits, gotLen, gotOK, tt.wantLen, tt.wantOK)
			}
		})
	}
}

// 空の符号集合（minLen == 0）に対しては常に不一致を返すこと（0 除算・
// 範囲外アクセスを起こさないことの回帰ガード）。
func TestMatchAreaCodeEmptySet(t *testing.T) {
	if _, ok := matchAreaCode(map[string]bool{}, 0, 0, "0312345678"); ok {
		t.Error("空の符号集合は常に不一致になるべき")
	}
}
