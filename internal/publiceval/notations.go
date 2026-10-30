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
	"officer-title",        // 役員の肩書き（代表取締役・取締役・監査役・代表者氏名 等）
	"professional-party",   // 士業・裁判官・当事者・事業者のラベル、業務禁止命令の名宛人
	"yago-kojin",           // 屋号こと氏名、氏名（個人／個人事業主）
	"contact-tel",          // 問合せ先の「役職 + 姓 + Tel」
	"contact-extension",    // 問合せ先の内線
	"contact-reading",      // 問合せ先の読み括弧
	"gov-title",            // 〜官（調整官・専門官・推進官 等）の問合せ先
	"name-spacing",         // 姓と名の間の複数空白（PDF レイアウト抽出）
	"cjk-radical",          // 康熙部首・部首補助の混入
	"variant-kanji",        // 異体字（﨑・髙・𠮷）
	"form-word",            // 項目名・様式名の誤検出型（陰性のみ）
	"name-reading",         // 空白区切りの姓名 + 空白区切りの読み括弧、担当 + 姓（よみ）
	"title-line-end",       // 職名 + 空白区切りの姓名で終わる行
	"honorific-compound",   // 敬称と同じ字を含む一般語（多様・編さん・両殿下・夫婦別氏・〜氏遺跡・自治体名 + 様・社殿・さんぽ・故人）
	"tanto-dept-slash",     // 担当欄の「部署／姓」
	"tanto-list",           // 担当欄に並べた複数の姓（担当：<姓>・<姓>）
	"org-head-colon",       // 法人紹介の「理事長：<姓><名>」
	"lecturer-label",       // 講師・審査員等のラベル + 氏名
	"shi-affiliation",      // 人物紹介の「<姓><名>氏（<所属>）」
	"koseki-todoke",        // 広報紙の戸籍の届出欄（出生届・死亡届・婚姻届）
	"title-honorific-wide", // 宛名欄の均等割付「<村>長 <姓>      <名>   様」
	"committee-list",       // 会議録の出席者欄「<姓><名>会長、<姓><名>委員、」
	"lecturer-space",       // 空白区切りの「講師 <姓> <名>さん」
	"tanto-space",          // 様式の「担当者 (<職>) <姓> <名>」
	"grade-prefix",         // 学年の直後の氏名「6年生<姓><名>さん」
	"tanto-wide",           // 担当欄の均等割付「担当：<姓>       <名>」
	"exec-title-wide",      // 代表者欄の均等割付「代表取締役     <姓>      <名>」
	"title-prefix",         // 職名に地続きの氏名「<町>町長<姓><名>様」
	"org-head-ceo",         // 法人紹介「代表取締役社長 CEO：<姓> <名>）」
	"seat-roster",          // 会議録の議席番号「1番     <姓>    <名>」
	"reading-after-no",     // 助詞「の」に続く「<姓> <名>（<せい> <めい>）」
	"tanshin-header",       // 決算短信の表紙「(役職名) <役職> (氏名) <姓> <名>」と「代表取締役社長 ＣＯＯ <姓> <名>」
	"permit-number",        // 許可・登録番号「第<12 桁>号」（陰性）と、囲まれていない個人番号（陽性）
	"lecturer-space-paren", // 敬称のない講座案内「・講師 <姓> <名>（<所属><職名>）」
	"director-credit",      // 出演作品一覧「「<作品名>」監督：<姓><名>」
	"sensei-line",          // 講師一覧の行「<姓> <名> 先生」
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
	pos("contact-tel", role, "課長補佐兼係長 "+n(3).sur+" 電話 000-000-0000")
	pos("contact-tel", role, "雇用推進課        課長 "+n(4).sur+" 電話 000-000-0000")

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
	pos("title-line-end", role, "理事長　"+full(3, "　"))
	pos("title-line-end", role, "架空県知事　"+full(4, "　"))
	pos("title-line-end", role, "                    契約責任者 "+full(5, " "))
	neg("title-line-end", "会長 挨拶 全文")
	neg("title-line-end", "理事長 "+full(0, " ")+" が出席した")
	pos("title-line-end", role, "架空機構 施設長             "+full(1, "    ")+"氏")
	pos("title-line-end", role, "架空法人       代表社員     "+full(2, "    ")+" 氏")
	pos("title-line-end", role, "架空大学    教授    "+full(3, "    ")+" 氏")
	neg("title-line-end", "教授 "+full(4, " ")+" が講演した")

	// 担当欄の「部署／姓」（調査公表資料の調査主体・委託先欄）
	pos("tanto-dept-slash", role, "【調査主体】架空機構（担当：調査部／"+n(1).sur+")")
	pos("tanto-dept-slash", role, "株式会社サンプル（担当：社会情報部／"+n(2).sur+"、"+n(3).sur+")")
	neg("tanto-dept-slash", "（担当：調査部／窓口)")

	// 担当欄に複数の姓を中黒・読点で並べた表記（2 人目以降）
	pos("tanto-list", role, "報 道 発 表 資 料      担当："+n(0).sur+"・"+n(1).sur+"・"+n(2).sur)
	pos("tanto-list", role, "架空機構 広報課（担当者："+n(3).sur+"、"+n(4).sur+"）")
	pos("tanto-list", role, "道路交通課 担当："+n(5).sur+"・"+n(0).sur+" TEL：000-000-0000")
	neg("tanto-list", "担当：総務・企画")

	// 報道発表の冒頭の法人紹介（法人の長 + コロン + 氏名）
	pos("org-head-colon", role, "架空研究機構（架空県架空市、理事長："+full(1, "")+"、以下「機構」）は")
	pos("org-head-colon", role, "架空機構（理事長："+full(2, "")+"    本部：架空県）")
	neg("org-head-colon", "（理事長：未定、以下「機構」）")

	// 講座・催しの案内の講師・審査員ラベル + 氏名（敬称なし・先生・氏・さん、2 人目を含む）
	pos("lecturer-label", role, "講師："+full(0, "")+"先生・"+full(1, "")+"先生")
	pos("lecturer-label", role, "◆講師："+full(2, ""))
	pos("lecturer-label", role, "講師："+full(3, "　")+"氏（株式会社架空）")
	pos("lecturer-label", role, "講師／"+full(4, "")+"氏〔架空大学教授〕")
	pos("lecturer-label", role, "審査員："+full(5, "")+"さん")
	neg("lecturer-label", "講師：教育委員会主事（学芸員）")
	neg("lecturer-label", "講師：架空警察署 生活安全課")
	neg("lecturer-label", "講師：架空クラブ")

	// 人物紹介の「<姓><名>氏（<所属>）」
	pos("shi-affiliation", role, "会長に"+full(0, "")+"氏（架空協会）が就任しました")
	pos("shi-affiliation", role, full(1, " ")+" 氏 〔架空大学〕")
	neg("shi-affiliation", "足利尊氏（室町幕府の初代将軍）")

	// 広報紙の戸籍の届出欄（出生・死亡・婚姻）
	pos("koseki-todoke", role, "死亡届（"+n(2).sur+"　ハナさん）")
	pos("koseki-todoke", role, "出生届（"+n(3).sur+"　ゆいちゃん）")
	pos("koseki-todoke", role, "婚姻届（"+full(4, "　")+"さん・"+full(5, "　")+"さん）")
	neg("koseki-todoke", "出生届（記入例）")

	// 宛名欄の均等割付（<村>長 <姓>      <名>   様）
	pos("title-honorific-wide", role, "架空村長 "+full(0, "      ")+"   様")
	pos("title-honorific-wide", role, "架空町長 "+full(1, "           ")+"   殿")
	neg("title-honorific-wide", "架空村長 会議      資料")

	// 会議録の出席者欄（<姓><名>会長、<姓><名>委員、）
	pos("committee-list", role, "出席委員 "+full(0, "")+"会長、"+full(1, "")+"委員、")
	pos("committee-list", role, "＜委員＞ "+full(2, "")+"副会長、"+full(3, "")+"委員")
	neg("committee-list", "人権擁護委員、民生委員、主任児童委員、社会教育委員、")
	neg("committee-list", full(4, "")+"委員会の開催について")

	// 空白区切りの講師欄（敬称必須）
	pos("lecturer-space", role, "（１）講師 "+full(4, " ")+"さん")
	pos("lecturer-space", role, "講師   "+full(5, "　")+"氏")
	neg("lecturer-space", "講師 派遣事業のご案内")

	// 様式の担当者欄（コロンなし・空白区切り）
	pos("tanto-space", role, "担当者 教頭 "+full(0, " ")+"           電話番号")
	pos("tanto-space", role, "担当者 "+full(1, " "))
	neg("tanto-space", "担当者 総務 企画")

	// 学年の直後の氏名（学年を範囲に含めない）
	pos("grade-prefix", "person-name-high-recall", "架空小学校6年生"+full(2, "")+"さんが訪れました")
	pos("grade-prefix", "person-name-high-recall", "2年"+full(3, "")+"さんの作品")
	neg("grade-prefix", "5年間様子を見た中で")

	// 担当欄の均等割付（姓と名の間が 2〜10 空白）
	pos("tanto-wide", role, "担当："+full(0, "       "))
	pos("tanto-wide", role, "○担当者名："+full(1, "         ")+"   電話 000-000-0000")
	neg("tanto-wide", "担当：総務       企画")

	// 代表者欄の均等割付（役職名 + 姓 + 4〜8 空白 + 名 + 行末）と所属括弧付きの広い空白
	pos("exec-title-wide", role, "架空建設株式会社 代表取締役     "+full(3, "      "))
	pos("exec-title-wide", role, "代表理事    "+n(4).sur+"   虹斗     氏（架空協会）")
	neg("exec-title-wide", "代表取締役     就任      挨拶")

	// 職名に地続きの氏名（職名を範囲に含めない）
	pos("title-prefix", "person-name-high-recall", "架空町長"+full(5, "")+"様")
	pos("title-prefix", "person-name-high-recall", "（委員長"+full(0, "")+"氏）")
	neg("title-prefix", "中央殿・右脇殿・左脇殿の3棟")
	neg("title-prefix", "市町村さんの方から意見がありました")
	neg("title-prefix", "寄付ありがとうございます（株式会社長浜架空電機様）")

	// 法人紹介で職名とコロンの間に「CEO」「グループ」「兼社長」や空白が入る表記と「<姓><名> 以下」
	pos("org-head-ceo", role, "架空製薬株式会社（本社：東京、代表取締役社長 CEO："+full(0, " ")+"）は、")
	pos("org-head-ceo", role, "架空ホールディングス（代表取締役会長兼社長CEO："+full(1, " ")+"、以下「当社」）")
	pos("org-head-ceo", role, "架空ライフグループ（代表取締役社長 グループ CEO："+full(2, " ")+"、以下「当社」）")
	pos("org-head-ceo", role, "架空機構(理事長 : "+full(3, " ")+"、以下「架空機構」)")
	pos("org-head-ceo", role, "架空通信株式会社（代表取締役社長："+full(4, "")+" 以下、架空通信）")
	neg("org-head-ceo", "代表取締役社長 CEO：就任挨拶のお知らせ")

	// 会議録の出席者表の議席番号 + 空白区切りの姓名
	pos("seat-roster", role, "出席   委    員     1番     "+full(5, "    "))
	pos("seat-roster", role, "会長        ５番   "+full(0, "   "))
	neg("seat-roster", "３番   議案   説明")
	neg("seat-roster", "日程第１番   報告   事項")

	// 助詞「の」に続く読み括弧付きの姓名
	pos("reading-after-no", role, "当日は、架空大学の"+n(1).sur+" 大（"+n(1).surYomi+" まさる）教授による講演")
	neg("reading-after-no", "架空市の中央 公園（ちゅうおう こうえん）の整備")

	// 決算短信・適時開示の表紙の括弧書きラベルと、役職名と氏名の間の CEO・COO
	pos("tanshin-header", role, "代   表   者 (役職名) 代表取締役社長  (氏名) "+full(0, " "))
	pos("tanshin-header", role, "問合せ先責任者 (役職名) 常務取締役管理本部長  (氏名) "+full(1, " ")+"   (TEL) 00-0000-0000")
	pos("tanshin-header", role, "代表者 （役職名）代表取締役社長 （氏名）"+full(2, ""))
	pos("tanshin-header", role, "架空製作所 代表取締役社長 ＣＯＯ "+full(3, " "))
	pos("tanshin-header", role, "代表者     （役職名） 代表取締役社長       （氏名）"+full(4, "                 "))
	pos("tanshin-header", role, "問合せ先責任者 (役職名) 総務部長 (氏名) "+full(5, " ")+" TEL 00-0000-0000")
	neg("tanshin-header", "代表者 (役職名) 代表取締役社長  (氏名) 未定")
	neg("tanshin-header", "(役職名)及び(氏名)を記入してください")
	neg("tanshin-header", "代表取締役社長 ＣＯＯ 就任のお知らせ")

	// 許可・登録番号「第<12 桁>号」（検査用数字を満たす 12 桁でもマイナンバーではない）
	neg("permit-number", "古物商許可番号 架空県公安委員会 第123456789018号")
	neg("permit-number", "許可番号：第 123456789018 号")
	// 自リポジトリ走査（CI の dogfooding）で検出されないよう、ダミー番号は分割して書く。
	pos("permit-number", "jp-my-number", "個人番号 "+"1234567890"+"18")

	// 敬称のない講座案内の講師欄（所属・職名の括弧が続く）
	pos("lecturer-space-paren", role, "・講師 "+full(0, " ")+"（架空センター副主幹）")
	pos("lecturer-space-paren", role, "・講師 "+full(1, " ")+"（架空調査事務所文化財主任）             ・申込 不要")
	pos("lecturer-space-paren", role, "講演者 "+full(2, "　")+"（架空大学教授）")
	neg("lecturer-space-paren", "講師 派遣事業（予定）")
	neg("lecturer-space-paren", "講師 架空 協会（予定）")

	// 出演作品一覧の監督クレジット（作品名の閉じかぎ括弧の後）
	pos("director-credit", role, "’22年　「架空の物語」 監督："+full(3, ""))
	pos("director-credit", role, "「架空の夜」監督　"+full(4, " "))
	pos("director-credit", role, "’24年　「架空」監督　"+full(5, "")+"　※声の出演のみ")
	pos("director-credit", role, "’25年  「架空忍者」監督:"+full(0, ""))
	neg("director-credit", "「架空法」監督官庁への届出")
	neg("director-credit", "「架空展」監督 指導のもと")
	neg("director-credit", "監督：未定")

	// 講師一覧の 1 行「<姓> <名> 先生」
	pos("sensei-line", role, full(1, " ")+" 先生")
	pos("sensei-line", role, full(2, " ")+" 先生・")
	neg("sensei-line", "校長 先生")
	neg("sensei-line", "担任の 先生")
	neg("sensei-line", "担当 未定 先生")

	// 記入方法の説明が氏名ラベルに続く形（辞書不一致の値を拾う Low の強ラベル）
	neg("form-word", "お名前（フルネーム、フリガナ）、生年月日を入力")
	neg("form-word", "氏名（自署）")
	neg("form-word", "氏名（ふりがな）")
	neg("form-word", "氏名：団体名・職・氏名")
	neg("form-word", "氏名（法人にあっては名称及び代表者の氏名）")
	neg("form-word", "氏名：      電話番号：")
	neg("form-word", "入札者の住所（所在地）、氏名（法人")
	neg("form-word", "氏名（複数名の場合は代表者）")
	neg("form-word", "氏名：カタカナで記入")
	neg("form-word", "氏名（社名）")
	neg("form-word", "お名前（かな）")
	neg("form-word", "氏名（敬称略）")
	neg("form-word", "氏名(名称及び代表者職氏名)")

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
	neg("honorific-compound", "北九州市様にご導入いただきました")
	neg("honorific-compound", "兵庫県様との協定")
	neg("honorific-compound", "横須賀市さんとの連携")
	neg("honorific-compound", "荒川さんぽ")
	neg("honorific-compound", "架空東照宮社殿特別公開")
	neg("honorific-compound", "川越城本丸御殿")
	neg("honorific-compound", "静岡県御殿場市")
	neg("honorific-compound", "同町殿ヶ谷の調査")
	neg("honorific-compound", "浄水場沈殿池清掃")
	neg("honorific-compound", "故・"+full(4, "")+"氏")
	pos("honorific-compound", "person-name-high-recall", "交通事故 "+full(5, "")+"様")
	pos("honorific-compound", "person-name-high-recall", n(0).sur+"殿")
	neg("honorific-compound", "株主様向けイベントのご案内")
	neg("honorific-compound", "個人投資家様向けオンライン会社説明会")
	neg("honorific-compound", "里親さんを知る日")
	neg("honorific-compound", "株式会社架空建設様から寄附をいただきました")
	neg("honorific-compound", "広報さんむ 10月号")
	neg("honorific-compound", "子供さんの健康相談")
	neg("honorific-compound", "サンタさんがやってくる")
	neg("honorific-compound", "出荷農家さん募集中")
	neg("honorific-compound", "妊婦さんや産婦さんの健康")
	neg("honorific-compound", "架空神社宮司さんによる解説")
	neg("honorific-compound", "架空市災害協力会様に感謝状を贈呈しました")
	neg("honorific-compound", "旧"+n(0).sur+"印刷さんのところを整備しました")
	neg("honorific-compound", "5年間様子を見た中で")
	neg("honorific-compound", "法人・事業主様の不動産のご相談")
	neg("honorific-compound", "対象株主様へのご案内")
	neg("honorific-compound", "新TVCM「義姉さんの家」篇")
	neg("honorific-compound", "架空紡績(株) 架空川工場様　隣接地")
	neg("honorific-compound", "販売店様向けサービス")
	neg("honorific-compound", "売主様にお手間もご負担も掛けません")
	neg("honorific-compound", "ページをご覧ください（架空製紙連合会様HPより）")
	neg("honorific-compound", "企業様・団体様の販促イベント")
	neg("honorific-compound", "放送局様などの公開録画イベント")
	neg("honorific-compound", "神父様、ありがとうございました")
	neg("honorific-compound", "声優さんによる読み聞かせ")
	neg("honorific-compound", "代理人様の場合は代理人確認書類")
	neg("honorific-compound", "将軍様の包囲網")
	neg("honorific-compound", "〔講演会〕白描源氏絵の美")
	pos("honorific-compound", "person-name-high-recall", n(0).sur+"源氏の新しい作品集")
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
