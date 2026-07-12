package dict

import "testing"

// ValidAreaCode は埋め込み済みの area_codes.txt（総務省公表の全市外局番を
// 収録した完全版、387 件）に対して、先頭から最長一致する市外局番の実在を
// 判定する。
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
		{"0466221111", 4, true}, // 0466（藤沢）+ 6 桁
		// 01267（岩見沢市宝水町・三笠市）は 0126（岩見沢市の残部・美唄市など）の
		// 5 桁への階層的な拡張。5 桁のほうが実在するので最長一致で 5 桁を採用する。
		{"0126712345", 5, true},
		// 同じ "0126" 始まりでも 5 桁目が "7" でなければ 5 桁側は実在しないため、
		// 4 桁の "0126" に一致する（美唄市など）。
		{"0126123456", 4, true},
		{"0138123456", 4, true}, // 0138（函館）+ 6 桁
		// 収録されていないプレフィックス（"02" 台の実在市外局番は 022〜029 のみで
		// "020" は存在しない）。
		{"0212345678", 0, false},
		{"0200000000", 0, false},
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
