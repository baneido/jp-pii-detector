// Package corpusv2 は、全ルールの陽性候補と hard negative を決定的に合成し、
// PR 時の精度ゲート（internal/publiceval）が使う公開合成コーパスを作る。
// 生成値は収集データではなく、由来を source_class / tags で明示する。
package corpusv2

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

const MinPositiveCasesPerRule = 10

// PublicSyntheticSeed は公開合成コーパス（PublicSynthetic）の固定シード。
const PublicSyntheticSeed = 20261023

// AllRuleIDs は評価対象になりうる全ルール ID（既定・高再現率・名簿ファイル判定）を
// 昇順で返す。
func AllRuleIDs() []string { return allRuleIDs() }

// PublicSynthetic は非公開コーパスを一切使わず、このパッケージの決定的な合成器
// （positiveCandidates / hardNegativeCases）だけで作る公開評価ケースを返す。
// 全ルールの陽性候補（Want のみ。span は検出器から逆算しない）と hard negative を
// 含み、PR 時の精度ゲート（internal/publiceval）が使う。検出器の出力でケースを
// 選別・注釈しないため、ルールが劣化すればそのまま FN/FP として現れる。
// 同じ seed からは常に同じケース列を返す。
func PublicSynthetic(seed int) []evalcase.Case {
	var out []evalcase.Case
	for _, id := range allRuleIDs() {
		for i, c := range positiveCandidates(id, seed) {
			c.ID = fmt.Sprintf("public-%s-%03d", id, i+1)
			c.SourceClass = "public-synthetic"
			c.Tags = appendUnique(c.Tags, "source:public-synthetic", "polarity:positive", "rule:"+id)
			out = append(out, c)
		}
	}
	for i, c := range hardNegativeCases(seed) {
		c.ID = fmt.Sprintf("public-hard-negative-%03d", i+1)
		c.SourceClass = "hard-negative"
		c.Tags = appendUnique(c.Tags, "source:public-synthetic", "polarity:negative")
		out = append(out, c)
	}
	return out
}

func allRuleIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, r := range rule.Builtin() {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, id := range rule.NameRosterRuleIDs() {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func positiveCandidates(id string, seed int) []evalcase.Case {
	var out []evalcase.Case
	postalCodes := dict.SamplePostalCodes(30)
	romanizedNames := romajiNames()
	for i := 0; i < 30; i++ {
		d := digitRun(seed+i+17, 20)
		// 公開テストでも使われる代表的な合成名。ケース識別子を値の外へ置き、
		// コーパス内の完全重複を避ける。
		name := syntheticFullName()
		casePrefix := fmt.Sprintf("case_id=%02d ", i+1)
		switch id {
		case "jp-my-number":
			switch i {
			case 0:
				// ドット区切り6-6（区切り表記ゆれ新パターンの合成ポジティブ）。
				num := myNumber(seed + i)
				out = append(out, lineCase("マイナンバー: "+num[:6]+"."+num[6:]))
			default:
				out = append(out, lineCase("マイナンバー: "+myNumber(seed+i)))
			}
		case "jp-phone-number":
			value := "090-" + d[:4] + "-" + d[4:8]
			switch i {
			case 0:
				out = append(out, evalcase.Case{File: "added.txt", Diff: []evalcase.DiffLine{{Text: "TEL: " + value, Added: true}}, Tags: []string{"layout:diff"}})
			case 1:
				out = append(out, evalcase.Case{File: "user.json", Content: "{\n  \"phone\": \"" + value + "\"\n}", Tags: []string{"file-format:json", "layout:content"}})
			case 2:
				// 保護系ポジティブ（NegativeContextAdjacentLabelOnly の保護規則
				// 固定）。「お客様番号」は「番号」で終わるが numberingLabelPrefixes
				// の明示語彙のどれとも完全一致しないため、採番ラベル接尾辞
				// ヒューリスティックを適用しない AdjacentLabelOnly では誤って
				// 抑制されない、採番風だが電話の実値。
				out = append(out, lineCase("お客様番号 "+value))
			default:
				out = append(out, lineCase("TEL: "+value))
			}
		case "jp-postal-code":
			if len(postalCodes) > i {
				code := postalCodes[i]
				out = append(out, lineCase("郵便番号: "+code[:3]+"-"+code[3:]))
			}
		case "jp-address":
			switch i {
			case 0:
				// ラベル付き都道府県なし形（jp-address 第 3 エントリの合成ポジティブ）。
				// 神南は実在町字（dict.MunicipalityThenTownMatch）のため High twin が
				// 成立するはず。
				out = append(out, lineCase("住所: 渋谷区神南1-2-3")) // jp-pii-detector:ignore
			case 1:
				// 同じくラベル付き都道府県なし形だが、市区町村直後が ABR 町字マスターに
				// 存在しない語（架空坂。TestPromotionContextWindowBoundary と同じ、
				// 町字マスターに前方一致しない架空の町名）で、町字辞書昇格 twin ではなく
				// 市区町村レベルの辞書ゲートだけに依存する形をあわせて確認する。
				out = append(out, lineCase("住所: 渋谷区架空坂1-2-3")) // jp-pii-detector:ignore
			default:
				out = append(out, lineCase(fmt.Sprintf("住所: 東京都渋谷区神南%d丁目%d番%d号", i%9+1, i%20+1, i%15+1)))
			}
		case "email-address":
			out = append(out, lineCase("連絡先: corpusv2-"+digitRun(seed+i+90, 8)+"@baneido.com"))
		case "email-address-eai":
			// 文字列を分割し、dogfood がコーパス構築コード自体を PII として
			// 報告しないようにする。実行時には日本語ローカル部の EAI になる。
			out = append(out, lineCase("連絡先: 利用者"+digitRun(seed+i+90, 4)+"@"+"baneido.com"))
		case "email-address-confusable":
			// キリル小文字 s（U+0455）を ASCII 中心ローカル部へ 1 文字だけ混入。
			out = append(out, lineCase("連絡先: u"+"ѕ"+"er"+digitRun(seed+i+90, 4)+"@"+"baneido.com"))
		case "credit-card":
			out = append(out, lineCase("カード番号: "+group(cardNumber(seed+i), []int{4, 4, 4, 4}, "-")))
		case "jp-drivers-license":
			out = append(out, lineCase("免許証番号: "+strconv.Itoa(30+i%20)+d[:10]))
		case "jp-passport":
			out = append(out, lineCase("パスポート番号: AB"+d[:7]))
		case "jp-pension-number":
			out = append(out, lineCase("基礎年金番号: "+d[:4]+"-"+d[4:10]))
		case "jp-residence-card":
			out = append(out, lineCase("在留カード番号: AB"+d[:8]+"CD"))
		case "jp-bank-account":
			switch i {
			case 0:
				// 空白区切り（3+4、区切り表記ゆれ新パターンの合成ポジティブ）。
				out = append(out, lineCase("口座番号: "+d[:3]+" "+d[3:7]))
			default:
				out = append(out, lineCase("口座番号: "+d[:7]))
			}
		case "jp-yucho-account":
			number := d[4:10] + "1"
			symbol := yuchoSymbol("1"+d[:2], number)
			out = append(out, lineCase("ゆうちょ銀行 記号"+symbol+"-"+number))
		case "jp-birthdate":
			out = append(out, lineCase(fmt.Sprintf("生年月日: %d年%d月%d日", 1970+i%35, i%12+1, i%27+1)))
		case "jp-health-insurance":
			out = append(out, lineCase("健康保険 保険者番号: "+d[:8]))
		case "jp-employment-insurance":
			out = append(out, lineCase("雇用保険被保険者番号: "+d[:4]+"-"+d[4:10]+"-"+d[10:11]))
		case "jp-kaigo-insurance":
			out = append(out, lineCase("介護保険 被保険者証番号: "+d[:10]))
		case "jp-juminhyo-code":
			out = append(out, lineCase("住民票コード: "+d[:11]))
		case "jp-invoice-number":
			out = append(out, lineCase("インボイス登録番号: T"+corporateNumber(d[:12])))
		case "person-name":
			out = append(out, lineCase(casePrefix+"氏名: "+name))
		case "jp-address-high-recall":
			// ラベルなし形（jp-address 第 3 エントリはラベル必須のため、この形には
			// 発火しない）。ラベル付きのまま（旧「住所: 渋谷区神南N-N-N」）だと、
			// 新しい jp-address 第 3 エントリが同じ値を検出し、high-recall
			// プロファイルで Want=jp-address-high-recall のケースに jp-address が
			// 帰属して row FP/FN が発生する（internal/rule/builtin.go の jp-address
			// 第 3 エントリのコメント参照）。
			out = append(out, lineCase(fmt.Sprintf("渋谷区神南%d-%d-%d", i%9+1, i%20+1, i%15+1)))
		case "person-name-role-label":
			out = append(out, lineCase(casePrefix+"担当: "+name))
		case "person-name-high-recall":
			// 敬称アンカー専用になったため、担当ラベル形ではなく敬称付きの形を
			// 合成する（担当ラベルは既定ルール person-name-role-label が持つ）。
			// 「<姓> <名>様」の空白区切りの形は既定の person-name-role-label も拾うため、空白を除く。
			honorific := []string{"様", "さん", "氏", "殿"}[i%4]
			out = append(out, lineCase(casePrefix+strings.ReplaceAll(name, " ", "")+honorific))
		case "person-name-roster":
			// ラベルも敬称も無い羅列。ケース識別子を行として置くと
			// 「非空行に占める氏名行の割合」を下げてしまうため、casePrefix は
			// 使わず氏名の組み合わせ自体でケースを一意にする。
			roster := rosterNames(i)
			out = append(out, evalcase.Case{
				File:    fmt.Sprintf("roster_%02d.txt", i+1),
				Content: strings.Join(roster, "\n"),
				Tags:    []string{"layout:content"},
			})
		case "person-name-structured":
			switch i % 3 {
			case 0:
				// 「氏名:」の次行は既定の person-name が見出し行として拾う（detect.scanSectionHeadingNames）
				// ため、高再現率でだけ拾う TSV の氏名列を使う。
				out = append(out, evalcase.Case{File: "people.tsv", Content: "氏名\tメモ\n" + name + "\t" + casePrefix, Tags: []string{"file-format:tsv", "layout:content"}})
			case 1:
				out = append(out, evalcase.Case{File: "people.csv", Content: "氏名,メモ\n" + name + "," + casePrefix, Tags: []string{"file-format:csv", "layout:content"}})
			case 2:
				out = append(out, evalcase.Case{File: "dump.sql", Content: "INSERT INTO users (氏名, memo) VALUES ('" + name + "', '" + casePrefix + "');", Tags: []string{"file-format:sql", "layout:content"}})
			}
		case "person-name-romaji":
			romaji := romanizedNames[i%len(romanizedNames)]
			if i%3 == 0 {
				out = append(out, evalcase.Case{File: "person.json", Content: fmt.Sprintf("{\"case_id\": %d, \"full_name\": \"%s\"}", i+1, romaji), Tags: []string{"file-format:json", "layout:content"}})
			} else {
				out = append(out, lineCase(casePrefix+"full_name: "+romaji))
			}
		}
	}
	for i := range out {
		out[i].Want = []string{id}
	}
	return out
}

// yuchoSymbol は先頭 3 桁と末尾固定 0 から、公式式を満たす検査数字を
// 4 桁目へ付与する。評価値は収集した実値ではなく決定的に合成する。
func yuchoSymbol(first3, number string) string {
	for check := byte('0'); check <= '9'; check++ {
		symbol := first3 + string(check) + "0"
		if checksum.YuchoAccount(symbol, number) {
			return symbol
		}
	}
	panic("ゆうちょ記号の検査数字を生成できません")
}

func hardNegativeCases(seed int) []evalcase.Case {
	out := make([]evalcase.Case, 0, 40)
	add := func(family, text string) {
		out = append(out, evalcase.Case{Line: text, Tags: []string{"scenario:hard-negative-" + family}})
	}
	for i, label := range []string{"受注ID", "受付番号", "トランザクション", "shipment_id=", "管理キー"} {
		// 12桁業務IDが偶然マイナンバーの検査数字を満たす既知FP系統。
		add("business-id", label+" "+myNumber(seed+500+i)+" を処理")
	}
	// 負文脈「隣接ラベル」判定のグルー許容（hasLabelBefore）と採番ラベル
	// 接尾辞ヒューリスティック（hasNumberingSuffixBefore）が対象とする
	// 表記ゆれ（助詞・コロン・イコールでラベルと値が途切れる形）を、上の
	// 空白区切り系統に加えて評価コーパスにも反映する。
	add("business-id", "受付番号は"+myNumber(seed+920)+"です")
	add("business-id", "ジョブID: "+myNumber(seed+921))
	add("business-id", "発注コード="+myNumber(seed+922))
	add("business-id", "管理キー: "+myNumber(seed+923))
	add("model", "海外パスポート対応 型番: TK"+digitRun(seed+924, 7))
	testPANs := wellKnownTestPANs()
	for i, label := range []string{"決済sandboxのテストカード", "payment fixture", "QA用PAN", "テスト決済", "カードブランド試験"} {
		add("test-pan", label+" "+testPANs[i])
	}
	for i, label := range []string{"リビジョン", "リリース"} {
		add("revision", fmt.Sprintf("%s %d-%s-%d をデプロイ", label, 2024+i, digitRun(seed+800+i, 6), i+3))
	}
	for i, label := range []string{"部品ロット", "製造ロット"} {
		add("lot", fmt.Sprintf("%s %s-%s-%d", label, digitRun(seed+820+i, 4), digitRun(seed+830+i, 6), i+4))
	}
	add("model", "在留カード対応リーダー 型番 AB"+digitRun(seed+840, 8)+"CD")
	add("model", "パスポート対応ケース 製品コード TK"+digitRun(seed+841, 7))
	add("money", "売上は"+digitRun(seed+850, 7)+"円です")
	add("money", "保険料"+digitRun(seed+851, 10)+"円を集計")
	add("count", "総件数は"+digitRun(seed+860, 8)+"件")
	add("count", "利用者"+digitRun(seed+861, 10)+"人の統計")
	add("date", fmt.Sprintf("処理日: %d-%02d-%02d", 2024, 4, 1))
	add("date", fmt.Sprintf("build %d-%s-%d", 2024, digitRun(seed+870, 6), 7))
	add("phone-like", "電話機SKU: 090-"+digitRun(seed+880, 4)+"-"+digitRun(seed+881, 4)+" (test model)")
	add("phone-like", "電話API version: 03-"+digitRun(seed+882, 4)+"-"+digitRun(seed+883, 4)+" (alpha)")
	postalCodes := dict.SamplePostalCodes(2)
	for i, label := range []string{"商品コード", "章番号"} {
		code := postalCodes[i]
		add("postal-like", "郵便発送の"+label+" "+code[:3]+"-"+code[3:]+"-REV")
	}
	add("account-like", "連番ID "+digitRun(seed+890, 7))
	add("account-like", "注文番号 "+digitRun(seed+891, 7))
	add("insurance-like", "ハッシュ "+digitRun(seed+900, 10)+"abcdef")
	add("insurance-like", "sequence="+digitRun(seed+901, 10))
	invoice := "T" + corporateNumber(digitRun(seed+910, 12))
	add("invoice-like", "型番 "+invoice+"X")
	add("invoice-like", "sample invoice "+invoice)
	name := syntheticFullName()
	romaji := strings.Join([]string{"Yamada", "Tarou"}, " ")
	add("name-like", "project_name: "+name)
	add("name-like", "商品名: "+name+"モデル")
	add("name-like", "filename: "+romaji)
	add("name-like", "project-name: "+romaji)
	add("address-like", fmt.Sprintf("通学区域%d丁目%d番%d号", 1, 2, 3))
	add("address-like", fmt.Sprintf("バージョン東京都版%d-%d-%d", 1, 2, 3))
	add("reserved-email", "連絡先 "+"user@"+"example.com")
	add("reserved-email", "メール "+"user@"+"foo.invalid")
	// #46 と同型の区切り表記ゆれ追加対応（本タスク）で導入した新パターンに
	// 対応する hard negative。RequireContext・NegativeContext・ValidateLine の
	// いずれかで正しく非検出になることを固定する。
	add("phone-url-slash", "https://example.com/090/"+digitRun(seed+940, 4)+"/"+digitRun(seed+941, 4))
	add("phone-url-slash", "api/v2/090/"+digitRun(seed+942, 4)+"/"+digitRun(seed+943, 4))
	add("phone-date-slash", fmt.Sprintf("更新日: %d/%02d/%02d", 2024, 4, 1))
	add("phone-version-mixed", "バージョン 0."+digitRun(seed+944, 4)+"-"+digitRun(seed+945, 4))
	add("mynumber-decimal", "value = "+digitRun(seed+946, 6)+"."+digitRun(seed+947, 6))
	add("mynumber-decimal", "個人番号"+digitRun(seed+948, 6)+"."+digitRun(seed+949, 6)+"円")
	add("bank-space-chain", "口座番号 "+digitRun(seed+950, 3)+" "+digitRun(seed+951, 4)+" "+digitRun(seed+952, 4))
	add("health-insurance-space-chain", "保険者番号 "+digitRun(seed+953, 4)+" "+digitRun(seed+954, 4)+" "+digitRun(seed+955, 4))
	return out
}

func lineCase(line string) evalcase.Case {
	return evalcase.Case{Line: line, Tags: []string{"layout:line"}}
}

func digitRun(seed, n int) string {
	var b strings.Builder
	for counter := 0; b.Len() < n; counter++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("jp-pii-private-corpus-v2:%d:%d", seed, counter)))
		for _, v := range sum {
			if b.Len() == n {
				break
			}
			b.WriteByte('0' + v%10)
		}
	}
	return b.String()
}

func myNumber(seed int) string {
	base := digitRun(seed+71, 11)
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(base[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return base + strconv.Itoa(check)
}

func cardNumber(seed int) string {
	payload := "4" + digitRun(seed+101, 14)
	return payload + strconv.Itoa(luhnCheckDigit(payload))
}

func luhnCheckDigit(payload string) int {
	sum := 0
	double := true
	for i := len(payload) - 1; i >= 0; i-- {
		d := int(payload[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return (10 - sum%10) % 10
}

func corporateNumber(base12 string) string {
	sum := 0
	for n := 1; n <= 12; n++ {
		p := int(base12[12-n] - '0')
		q := 1
		if n%2 == 0 {
			q = 2
		}
		sum += p * q
	}
	return strconv.Itoa(9-sum%9) + base12
}

func group(value string, widths []int, sep string) string {
	parts := make([]string, 0, len(widths))
	start := 0
	for _, width := range widths {
		parts = append(parts, value[start:start+width])
		start += width
	}
	return strings.Join(parts, sep)
}

func romajiNames() []string {
	pairs := [][2]string{
		{"Yamada", "Tarou"}, {"Tarou", "Yamada"}, {"Suzuki", "Hanako"},
		{"Satou", "Ichirou"}, {"Tanaka", "Kenta"}, {"Takahashi", "Misaki"},
		{"Itou", "Sakura"}, {"Watanabe", "Yuuki"}, {"Yamamoto", "Naoki"},
		{"Nakamura", "Akira"}, {"Kobayashi", "Haruka"}, {"Katou", "Megumi"},
		{"Yoshida", "Tsubasa"}, {"Yamaguchi", "Nanami"}, {"Matsumoto", "Satoshi"},
	}
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, strings.Join(pair[:], " "))
	}
	return out
}

func syntheticFullName() string {
	return strings.Join([]string{"山田", "太郎"}, "")
}

// rosterSurnames / rosterGivens は名簿ケース用の合成部品。姓と名を別々の
// リテラルとして持ち、実行時に連結する（syntheticFullName と同じ理由で、
// このソース自体が自己走査で氏名として検出されないようにするため）。
var (
	rosterSurnames = []string{"山田", "佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "中村", "小林", "加藤"}
	rosterGivens   = []string{"太郎", "花子", "一郎", "健太", "美咲", "次郎", "三郎", "陽子", "直樹", "恵子"}
)

// rosterNames は i 番目の名簿ケースに使う氏名を 3 件返す。姓・名のずらし方を
// 変えることで、ケース間で完全重複しない組み合わせを決定的に生成する。
func rosterNames(i int) []string {
	n := len(rosterSurnames)
	offsets := [][2]int{{0, 0}, {3, 7}, {5, 2}}
	out := make([]string, 0, len(offsets))
	for _, off := range offsets {
		out = append(out, rosterSurnames[(i+off[0])%n]+rosterGivens[(i+off[1])%n])
	}
	return out
}

// wellKnownTestPANs は決済事業者のsandboxで公知の非稼働番号だけを返す。
// 任意のLuhn妥当値を陰性扱いすると、偶然実在する番号を「偽陽性」と誤ラベルするため、
// hard negativeではこの集合に限定する。完全な番号リテラルはソースへ置かない。
func wellKnownTestPANs() []string {
	parts := [][]string{
		{"4111", "1111", "1111", "1111"},
		{"4242", "4242", "4242", "4242"},
		{"5555", "5555", "5555", "4444"},
		{"3782", "8224", "6310", "005"},
		{"3530", "1113", "3330", "0000"},
	}
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		out = append(out, strings.Join(item, ""))
	}
	return out
}

func appendUnique(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range dst {
		seen[value] = true
	}
	for _, value := range values {
		if value != "" && !seen[value] {
			dst = append(dst, value)
			seen[value] = true
		}
	}
	return dst
}
