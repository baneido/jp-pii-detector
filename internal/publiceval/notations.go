package publiceval

import (
	"fmt"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

// 公開文書の走査（自動改善サイクル）で見つけ、検出ロジックを直した表記を、
// 合成値だけで作り直した公開評価ケース。ゴールデンが新しい表記を含まないと、
// 修正の効果（と将来の後退）が public-eval の数値に現れないため加える。
//
// 収集した文書の本文・氏名・番号は一切使わない。氏名は架空の定番名（山田 太郎 等）を
// 姓・名の部品から実行時に組み立て（syntheticFullName と同じく、このソース自体が
// 自己走査で氏名として検出されないようにするため）、電話・内線は 0 だけの番号にする。
// 陽性はそのルールが検出すべき氏名・住所を含む行、陰性は同じ語彙を含むが個人を
// 指さない行（法人名・会議体・一般語・姓だけ・項目名）で、検出器の出力から
// ラベルを逆算しない。

// notationName は合成ケース用の架空の氏名と読み。
type notationName struct{ sur, given, surYomi, givenYomi string }

var notationNames = []notationName{
	{"山" + "田", "太" + "郎", "やま" + "だ", "たろう"},
	{"佐" + "藤", "花" + "子", "さと" + "う", "はなこ"},
	{"鈴" + "木", "一" + "郎", "すず" + "き", "いちろう"},
	{"高" + "橋", "健" + "太", "たか" + "はし", "けんた"},
	{"田" + "中", "美" + "咲", "たな" + "か", "みさき"},
	{"伊" + "藤", "直" + "樹", "いと" + "う", "なおき"},
}

// notationCategories は表記の分類（ケースの tag notation:<分類> と ID に使う）。
var notationCategories = []string{
	"officer-title",      // 役員の肩書き（代表取締役・取締役・監査役・代表者氏名 等）
	"professional-party", // 士業・裁判官・当事者・事業者のラベル、業務禁止命令の名宛人
	"yago-kojin",         // 屋号こと氏名、氏名（個人／個人事業主）
	"contact-tel",        // 問合せ先の「役職 + 姓 + Tel」
	"contact-extension",  // 問合せ先の内線
	"contact-reading",    // 問合せ先の読み括弧
	"gov-title",          // 〜官（調整官・専門官・推進官 等）の問合せ先
	"name-spacing",       // 姓と名の間の複数空白（PDF レイアウト抽出）
	"cjk-radical",        // 康熙部首・部首補助の混入
	"variant-kanji",      // 異体字（﨑・髙・𠮷）
	"form-word",          // 項目名・様式名の誤検出型（陰性のみ）
	"name-reading",       // 空白区切りの姓名 + 空白区切りの読み括弧、担当 + 姓（よみ）
	"title-line-end",     // 職名 + 空白区切りの姓名で終わる行
	"honorific-compound", // 敬称と同じ字を含む一般語（多様・編さん・両殿下・夫婦別氏・〜氏遺跡）
}

type notationCase struct {
	category string
	line     string
	want     string // 空なら陰性
}

func notationSpecs() []notationCase {
	n := func(i int) notationName { return notationNames[i%len(notationNames)] }
	full := func(i int, sep string) string { return n(i).sur + sep + n(i).given }
	var out []notationCase
	pos := func(cat, rule, line string) { out = append(out, notationCase{cat, line, rule}) }
	neg := func(cat, line string) { out = append(out, notationCase{cat, line, ""}) }
	const role = "person-name-role-label"

	// 役員の肩書き
	pos("officer-title", role, "代表者：代表取締役 "+full(0, " "))
	pos("officer-title", role, "（３）代 表 者：代表取締役 "+full(1, " "))
	pos("officer-title", role, "また、同社の代表取締役である"+full(2, "")+"は、法第16条違反により刑が確定した。")
	pos("officer-title", role, "（3）代表取締役（"+full(3, "")+"）に対する指示")
	pos("officer-title", role, "株式会社サンプル 代表取締役 "+full(4, " "))
	pos("officer-title", role, "株式会社テスト 取締役 "+full(5, " "))
	pos("officer-title", role, "監査役 "+full(0, "　"))
	pos("officer-title", role, "取締役社長（"+full(1, "")+"）")
	pos("officer-title", role, "株式会社サンプル 代 表 取 締 役   "+full(2, "   "))
	pos("officer-title", role, "同社の代表取締役であった"+full(3, "")+"及び従業員")
	pos("officer-title", role, "代表者氏名                  "+full(4, " "))
	pos("officer-title", role, "代表者の氏名   "+full(5, "   "))
	pos("officer-title", role, "代表者名："+full(0, "　"))
	neg("officer-title", "代表取締役 就任のお知らせ")
	neg("officer-title", "代表取締役（代表権を有する者）")
	neg("officer-title", "取締役会 決議事項")
	neg("officer-title", "監査役 監査報告")
	neg("officer-title", "取締役   "+n(1).sur)
	neg("officer-title", "代表者氏名 変更届")
	neg("officer-title", "代表者名 記載例")
	neg("officer-title", "代 表 取 締 役 選任の件")
	neg("officer-title", "代表者：株式会社サンプル")

	// 士業・裁判官・当事者・事業者のラベル、業務禁止命令
	pos("professional-party", role, "同訴訟代理人弁護士　"+full(1, "　"))
	pos("professional-party", role, "訴訟代理人弁理士　"+full(2, ""))
	pos("professional-party", role, "裁判長裁判官　"+full(3, ""))
	pos("professional-party", role, "申請代理人 司法書士 "+full(4, ""))
	pos("professional-party", role, "審査申立人　（総代）"+full(5, "　"))
	pos("professional-party", role, "原告 "+full(0, " "))
	pos("professional-party", role, "審査請求人　"+full(1, ""))
	pos("professional-party", role, "事業者："+full(2, " ")+"（65 歳）")
	pos("professional-party", role, "事  業  者："+full(3, " ")+"（65 歳）")
	pos("professional-party", role, "「"+full(4, "")+"」（以下「事業者」という。）に対し")
	pos("professional-party", role, full(5, "")+"に対する業務禁止命令")
	neg("professional-party", "弁護士法人サンプル")
	neg("professional-party", "弁護士会 会長")
	neg("professional-party", "弁護士 費用の負担")
	neg("professional-party", "裁判官 全員一致の意見")
	neg("professional-party", "弁護士 "+n(2).sur)
	neg("professional-party", "原告 主張の要旨")
	neg("professional-party", "被告 株式会社サンプル")
	neg("professional-party", "（総代）未定")
	neg("professional-party", "事業者：株式会社サンプル")
	neg("professional-party", "株式会社サンプルに対する業務禁止命令")
	neg("professional-party", "「株式会社サンプル」（以下「事業者」という。）")

	// 屋号こと氏名、氏名（個人）
	pos("yago-kojin", role, "事業者名：サンプル設備こと"+full(0, ""))
	pos("yago-kojin", role, "事業者であるテストアシスタンスこと"+full(1, "")+"（個人事業主）に対し、業務停止命令の処分を行いました。")
	pos("yago-kojin", role, "架空リユースセンターこと"+full(2, "　"))
	pos("yago-kojin", role, "Sample工房こと"+full(3, "")+"に対し指示を行った。")
	pos("yago-kojin", role, "また、県は、"+full(4, "")+"（個人）に対し、業務禁止命令の処分を行いました。")
	pos("yago-kojin", role, full(5, " ")+"（個人事業主）")
	neg("yago-kojin", "契約を締結することを停止するよう命じました。")
	neg("yago-kojin", "事業者（個人）に対する指示")
	neg("yago-kojin", "架空市民（個人）の意見")
	neg("yago-kojin", "サンプル設備こと未定")
	neg("yago-kojin", "テスト工房こと"+n(3).sur)

	// 問合せ先の「役職 + 姓 + Tel」
	pos("contact-tel", role, " 人事課長   "+n(0).sur+"   Tel 000-000-0000")
	pos("contact-tel", role, "学校連携・こども担当課長　　"+n(1).sur+"　　TEL 000-000-0000")
	pos("contact-tel", role, "総務課長 "+full(2, " ")+" 電話 000-000-0000")
	pos("contact-tel", role, "                            消費経済課長           "+n(3).sur+"      Tel 000-000-0000")
	neg("contact-tel", "課長 代理 Tel 000-000-0000")
	neg("contact-tel", "総務課長 不在 電話 000-000-0000")
	neg("contact-tel", "人事課長 Tel 000-000-0000")
	neg("contact-tel", "所長 室内 電話あり")

	// 問合せ先の内線
	pos("contact-extension", role, "総務部 人事課長            "+full(4, "    ")+"         （内線0000）")
	pos("contact-extension", role, "品質確保室長 "+n(5).sur+" （内線０００）")
	pos("contact-extension", role, "広報課長 "+full(0, " ")+"（内線 0000）")
	neg("contact-extension", "人事課長 会議 （内線0000）")
	neg("contact-extension", "品質確保室長 不在 （内線０００）")

	// 問合せ先の読み括弧
	pos("contact-reading", role, "建設産業第一課 課長補佐   "+n(1).sur+"（"+n(1).surYomi+"） （内線００００）")
	pos("contact-reading", role, "専門調査官 "+full(2, " ")+"（"+n(2).surYomi+" "+n(2).givenYomi+"） （内線0000）")
	pos("contact-reading", role, "代表者名："+full(3, "　")+"（"+n(3).surYomi+"　"+n(3).givenYomi+"）")
	neg("contact-reading", "課長補佐   会議（かいぎ） （内線0000）")
	neg("contact-reading", "課長補佐 "+n(4).sur+"（"+n(4).surYomi+"）が出席した")

	// 〜官の問合せ先
	pos("gov-title", role, "上下水道調整官 "+full(5, " ")+"（内線0000）")
	pos("gov-title", role, "総務部契約管理官      "+full(0, " ")+"  （内線 ０００）")
	pos("gov-title", role, "建設専門官 "+full(1, "  ")+" （内線0000）")
	pos("gov-title", role, "不動産業適正化推進官 "+n(2).sur+" （内線００００）")
	neg("gov-title", "上下水道調整官 会議 （内線0000）")
	neg("gov-title", "不動産業適正化推進官 会議 （内線0000）")
	neg("gov-title", "建設専門官 研修 （内線0000）")

	// 姓と名の間の複数空白
	pos("name-spacing", role, "    有限会社サンプル観光   取締役   "+full(3, "   ")+"   ※同社代理人弁護士同席")
	pos("name-spacing", role, "有限会社テスト観光   代表取締役   "+full(4, "   "))
	pos("name-spacing", role, "訴訟代理人弁護士   "+full(5, "   "))
	pos("name-spacing", role, "審査申立人   "+full(0, "  "))
	neg("name-spacing", "代表取締役      選任      決議")
	neg("name-spacing", "取締役 会長 退任")

	// 康熙部首・部首補助の混入（pdftotext の抽出で入る ⼤ ⽬ ⻑ ⼭ ⽥ 等）
	pos("cjk-radical", "jp-address", "所在地：⼤阪府"+"架空市本町１丁⽬２番３号") // jp-pii-detector:ignore
	pos("cjk-radical", "jp-address", "住所：東京都"+"架空区⻄町１丁⽬２番３号")  // jp-pii-detector:ignore
	pos("cjk-radical", role, "代表者：⼭"+"⽥ "+n(0).given)
	pos("cjk-radical", role, "人事課⻑ "+n(1).sur+" Tel 000-000-0000")
	neg("cjk-radical", "⻑期計画の策定")
	neg("cjk-radical", "⼤規模⼯事の⽇程")

	// 異体字（NFKC でも新字体に統合されない 﨑・髙・𠮷）
	pos("variant-kanji", role, "名 称 サンプル塗装こと山"+"﨑"+n(1).given+"（個人事業者）")
	pos("variant-kanji", role, "代表者名：髙"+"橋　"+n(2).given)
	pos("variant-kanji", role, "代表取締役 髙"+"橋 "+n(4).given)
	pos("variant-kanji", role, "審査請求人 𠮷"+"田 "+n(5).given)
	neg("variant-kanji", "髙品質の製品")
	neg("variant-kanji", "﨑の字の異体字表")

	// 項目名・様式名の誤検出型（高再現率の敬称アンカーが拾っていた）
	neg("form-word", "生徒氏名、学年、報告内容")
	neg("form-word", "職員氏名の一覧")
	neg("form-word", "申請書様式を使用する")
	neg("form-word", "共通様式により報告")
	neg("form-word", "別添様式２のとおり")
	neg("form-word", "印鑑届書様式")

	// 問合せ先の「役職 + 姓」の直後に電話番号が続く形（Tel・電話の前置きなし）
	pos("contact-tel", role, "共生社会推進課長 "+n(2).sur+" ０００－０００－００００")
	neg("contact-tel", "共生社会推進課長 会議 ０００－０００－００００")

	// 空白区切りの姓名 + 空白区切りの読み括弧（委員名簿・講演者紹介・あいさつ文）
	pos("name-reading", role, full(0, "　")+"（"+n(0).surYomi+"　"+n(0).givenYomi+"）")
	pos("name-reading", role, "委員長 "+full(1, " ")+"（"+n(1).surYomi+" "+n(1).givenYomi+"） 架空大学教授")
	pos("name-reading", role, "管理第一課長 "+full(2, " ")+"（"+n(2).surYomi+" "+n(2).givenYomi+"） （内線0000）")
	pos("name-reading", role, "担当　"+n(3).sur+"("+n(3).surYomi+")、"+n(4).sur+"("+n(4).surYomi+")")
	neg("name-reading", "東京　都庁（とうきょう　とちょう）")
	neg("name-reading", "会議 資料（かいぎ しりょう）")
	neg("name-reading", "担当　窓口(まどぐち)")
	neg("name-reading", full(5, "")+"（"+n(5).surYomi+n(5).givenYomi+"）の表記例") // 読みが 1 語なら対象外

	// 職名 + 空白区切りの姓名で終わる行（担当者一覧・発信者欄）
	pos("title-line-end", role, "河川技術部門担当 課長補佐 "+full(4, " "))
	pos("title-line-end", role, "架空庁長官    "+full(5, " "))
	pos("title-line-end", role, "副館長　"+full(0, "　"))
	neg("title-line-end", "課長 会議 室長")
	neg("title-line-end", "課長補佐 "+n(1).sur+" 担当")
	neg("title-line-end", "所長 "+full(2, " ")+" が出席した")

	// 記入方法の説明が氏名ラベルに続く形（辞書不一致の値を拾う Low の強ラベル）
	neg("form-word", "氏名（ふりがな）")
	neg("form-word", "氏名：団体名・職・氏名")
	neg("form-word", "氏名（法人にあっては名称及び代表者の氏名）")
	neg("form-word", "氏名（複数名の場合は代表者）")
	neg("form-word", "氏名：カタカナで記入")

	// 敬称と同じ字を含む一般語（高再現率の敬称アンカーが拾っていた）
	pos("honorific-compound", "person-name-high-recall", "本多"+"様より御連絡がありました")
	pos("honorific-compound", "person-name-high-recall", "喜多"+"さんに確認した")
	pos("honorific-compound", "person-name-high-recall", full(0, "")+"殿")
	neg("honorific-compound", "生物多様性の保全")
	neg("honorific-compound", "総合企画部多様性社会推進課")
	neg("honorific-compound", "県史編さんだより")
	neg("honorific-compound", "野外炊さん体験")
	neg("honorific-compound", "女王殿下の御来県")
	neg("honorific-compound", "皇族各殿下の御健勝")
	pos("honorific-compound", "person-name-high-recall", "架空宮妃"+n(1).given+"殿下の御来県")
	neg("honorific-compound", "選択的夫婦別氏制度")
	neg("honorific-compound", "架空朝倉氏遺跡の保存")
	neg("honorific-compound", "西山氏庭園の公開")
	return out
}

// NotationCases は notationSpecs を評価ケースへ変換する。同じコードからは
// 常に同じケース列を返す。
func NotationCases() []evalcase.Case {
	seq := map[string]int{}
	var out []evalcase.Case
	for _, s := range notationSpecs() {
		polarity := "negative"
		if s.want != "" {
			polarity = "positive"
		}
		seq[s.category+polarity]++
		c := evalcase.Case{
			ID:   fmt.Sprintf("public-notation-%s-%s-%03d", s.category, polarity[:3], seq[s.category+polarity]),
			Line: s.line,
			Tags: []string{"layout:line", "source:public-synthetic", "polarity:" + polarity, "notation:" + s.category},
		}
		if s.want != "" {
			c.SourceClass = "public-synthetic"
			c.Want = []string{s.want}
			c.Tags = append(c.Tags, "rule:"+s.want)
		} else {
			c.SourceClass = "hard-negative"
			c.Tags = append(c.Tags, "scenario:hard-negative-notation-"+s.category)
		}
		out = append(out, c)
	}
	return out
}

// notationCategoryOf は ID から分類名を返す（テスト・集計用）。
func notationCategoryOf(c evalcase.Case) string {
	for _, t := range c.Tags {
		if strings.HasPrefix(t, "notation:") {
			return strings.TrimPrefix(t, "notation:")
		}
	}
	return ""
}
