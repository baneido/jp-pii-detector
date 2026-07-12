// generateTowns は ABR（アドレス・ベース・レジストリ）町字マスター CSV から、
// 大字・町名（oaza_cho 列）の実在集合を internal/dict/towns.txt へ書き出す。
//
// KEN_ALL と異なり ABR の CSV はヘッダ行付きなので、列インデックス固定では
// なくヘッダ名（"oaza_cho" / "pref"）から列を解決する（フォーマット変更に
// 多少強く、取り違えのリスクも低い）。
package main

import (
	"archive/zip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// townOazaColumnName / townPrefColumnName は ABR mt_town_all.csv のヘッダに
// 現れる列名。大字・町名は "oaza_cho"、都道府県名は "pref"（件数の
// サニティ表示・47 都道府県網羅の確認用。towns.txt 自体には残さない）。
const (
	townOazaColumnName = "oaza_cho"
	townPrefColumnName = "pref"
)

// isCleanTownRune は towns.txt に残す文字（漢字・ひらがな・カタカナ・半角英数字）
// かどうかを返す。internal/rule/builtin.go の kanji / hiragana / katakana
// 文字クラス（jp-address-high-recall 等の住所パターンが使う）と同じ範囲を
// ミラーする。範囲外の文字（括弧・中点・補助漢字面のまれな異体字等）を含む
// 町字名は、そもそも住所パターンの正規表現がギャップとして捕捉できないため
// 収録しても死んだデータにしかならず、除外する。範囲を変える場合は
// builtin.go 側の定義と揃えること。
func isCleanTownRune(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF, r == 0x3005: // 漢字 + 々
		return true
	case r >= 0x3041 && r <= 0x3096: // ひらがな
		return true
	case r >= 0x30A1 && r <= 0x30FA, r == 0x30FC, r == 0x3099, r == 0x309A: // カタカナ + ー + 濁点半濁点
		return true
	case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		return true
	}
	return false
}

// townMinRuneLen は towns.txt に残す町字名の最小ルーン数。
//
// ABR には北海道の開拓地割に由来する 1 文字だけの町字名（"イ" "ロ" "ハ" の
// ような仮名 1 字、"上" "中" "新" "本" のような常用漢字 1 字）が 331 件
// 含まれる。これらは固有性がほぼなく、住所らしいテキストの先頭に来る
// ごくありふれた 1 文字（「新製品」「上司」等の書き出し）へ偶然前方一致
// しやすい。TownPrefixMatch は最長一致優先のため、ギャップの本当の語頭が
// 2 文字以上の実在町字名（例: 「上原」）であればそちらが優先されるが、
// ギャップの語頭がたまたま辞書にない語で、かつ 1 文字だけが辞書に実在する
// 場合に誤って昇格してしまう。この偶然一致は昇格専用エビデンスとしての
// 精度を大きく損なうため、2 文字未満の町字名は収録しない
// （昇格の取りこぼしは許容: 棄却には使わないため recall には影響しない）。
const townMinRuneLen = 2

// isCleanTownName は s（空でなく、正規化済み）が isCleanTownRune の範囲だけで
// 構成され、townMinRuneLen 以上の長さを持つかを返す。
func isCleanTownName(s string) bool {
	if s == "" {
		return false
	}
	n := 0
	for _, r := range s {
		if !isCleanTownRune(r) {
			return false
		}
		n++
	}
	return n >= townMinRuneLen
}

// normalizeTownName は ABR の生の oaza_cho 値を towns.txt 収録形へ正規化する。
//   - NFKC 正規化: CJK 互換漢字（"塚" の異体字コードポイント等、府県によっては
//     多数の実在町名がこの表記ゆれを持つ）を統一漢字面へ、全角英数字・全角括弧を
//     半角へ畳む。北海道の条丁目形（"西２条" 等）は全角数字を含むため、この
//     フォールドがないと半角数字前提の実行時テキスト（normalize.Line 適用後）と
//     照合できず収録しても一致しない。
//   - dict.NormalizeMunicipalityKa: ヶ→ケ。市区町村名辞書
//     （internal/dict/municipalities.txt）と同じ規則を両側（生成時・照合時）に
//     適用することで、表記ゆれのどちらでも一致させる。
func normalizeTownName(raw string) string {
	return dict.NormalizeMunicipalityKa(norm.NFKC.String(strings.TrimSpace(raw)))
}

func generateTowns(inputPath, outputPath string) error {
	towns := map[string]struct{}{}
	prefs := map[string]struct{}{}
	rows := 0
	dropped := 0

	handle := func(oaza, pref string) {
		rows++
		if pref != "" {
			prefs[pref] = struct{}{}
		}
		if strings.TrimSpace(oaza) == "" {
			return
		}
		cleaned := normalizeTownName(oaza)
		if !isCleanTownName(cleaned) {
			dropped++
			return
		}
		towns[cleaned] = struct{}{}
	}

	if err := forEachTownRow(inputPath, handle); err != nil {
		return fmt.Errorf("towns input: %w", err)
	}
	if len(towns) == 0 {
		return fmt.Errorf("no town names found in %s", inputPath)
	}

	if err := writeTowns(outputPath, towns); err != nil {
		return err
	}
	fmt.Printf("towns: %d unique (from %d rows, %d prefectures observed, %d rows dropped as empty/impure oaza_cho)\n",
		len(towns), rows, len(prefs), dropped)
	return nil
}

// forEachTownRow は path（CSV または zip）を ABR mt_town_all.csv 形式
// （ヘッダ行あり）として読み、データ行ごとに handle(oaza_cho, pref) を呼ぶ。
// KEN_ALL 系の forEachRecord はヘッダなし固定列前提のため流用せず、ヘッダ行から
// 列インデックスを解決する専用の読み取りを行う。
func forEachTownRow(path string, handle func(oaza, pref string)) error {
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return forEachTownRowInZip(path, handle)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readTownCSV(path, f, handle)
}

func forEachTownRowInZip(path string, handle func(oaza, pref string)) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()

	foundCSV := false
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(file.Name), ".csv") {
			continue
		}
		foundCSV = true
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = readTownCSV(file.Name, rc, handle)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !foundCSV {
		return fmt.Errorf("zip has no csv entries: %s", path)
	}
	return nil
}

func readTownCSV(name string, r io.Reader, handle func(oaza, pref string)) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("%s: reading header: %w", name, err)
	}
	oazaCol, prefCol := -1, -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case townOazaColumnName:
			oazaCol = i
		case townPrefColumnName:
			prefCol = i
		}
	}
	if oazaCol < 0 {
		return fmt.Errorf("%s: %q column not found in header %v", name, townOazaColumnName, header)
	}

	for {
		record, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(record) <= oazaCol {
			continue
		}
		pref := ""
		if prefCol >= 0 && prefCol < len(record) {
			pref = record[prefCol]
		}
		handle(record[oazaCol], pref)
	}
}

// townsHeader は internal/dict/towns.txt の先頭に埋め込む出典コメント。
// area_codes.txt（総務省一次データ）と同様、出典 URL・データ版・取得日・
// SHA-256・件数・ライセンスを記録する。
const townsHeader = `# internal/dict/towns.txt
#
# デジタル庁アドレス・ベース・レジストリ（ABR）「全国 町字マスター」由来の
# 大字・町名（oaza_cho 列）の実在集合。dict.TownPrefixMatch が
# jp-address-high-recall の昇格専用 Validate（市区町村マッチ直後のギャップが
# 実在町字名で始まる場合だけ Medium→High へ昇格。不一致は Medium のまま
# 据え置くだけで棄却には使わない）に使う。
#
# 出典: デジタル庁 アドレス・ベース・レジストリ Datasets「全国 町字マスター」
#   https://dataset.address-br.digital.go.jp/documents/b80e77a0e2d24e5692be4af885eb3de7
#   データ本体（mt_town_all.csv.zip）:
#   https://data.address-br.digital.go.jp/mt_town/mt_town_all.csv.zip
#   （取得時、上記 CloudFront 配信は国外 IP からのアクセスを拒否したため、実際の
#   取得は同一オブジェクトを配信するオリジンの公開 S3 バケット経由で行った。
#   Last-Modified がカタログ記載の最終更新日時と一致することを確認済み:
#   https://gov-csv-export-public.s3.ap-northeast-1.amazonaws.com/mt_town/mt_town_all.csv.zip）
# データ版（最終更新日時、カタログ記載）: 2026-07-03T06:50:13.000Z
# 取得日: 2026-07-12
# ライセンス: CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
#   出典表示: デジタル庁「アドレス・ベース・レジストリ」
# mt_town_all.csv.zip SHA-256: 25b692f4cba181bfbc98f438e77f2003b050aebbafe4b6a59c3bc6414ac16d24
#
# 生成: go run ./internal/dict/gen -towns -input mt_town_all.csv.zip -output internal/dict/towns.txt
#
# 抽出方法: oaza_cho 列（大字・町名。丁目・小字・番地は別列のためここには
# 含まれない）をユニーク化し、NFKC 正規化（全角英数字・CJK 互換漢字の統一漢字面
# への畳み込み）と dict.NormalizeMunicipalityKa（ヶ→ケ）を適用したうえで、
# 漢字・ひらがな・カタカナ・半角英数字のみからなる 2 文字以上のエントリだけを
# 収録した（internal/rule の住所パターンが捕捉できない文字を含むエントリ、
# および北海道の開拓地割由来の 1 文字だけの町字名（偶然の前方一致を招きやすい）
# は除外。詳細は internal/dict/gen/towns.go を参照）。
`

func writeTowns(path string, towns map[string]struct{}) error {
	names := make([]string, 0, len(towns))
	for t := range towns {
		names = append(names, t)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(townsHeader)
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('\n')
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
