package detect

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
)

// object_scope.go は JSON/YAML の「オブジェクト（マッピング）スコープ」に基づく
// 文脈付与（レコードスコープの本丸、フェーズ2）。source_context.go の
// statementContext は同一行の key=value/key: しか見ないため、JSON/YAML では
// 2 つの穴がある:
//
//  1. 親キーの文脈が子孫の行に伝播しない。例えば
//
//     phone:
//       home: 0466221111 // jp-pii-detector:ignore
//
//     のような YAML で、"home" 行は自分自身のラベル（home）しか持たず、
//     親キー "phone" の文脈（jp-phone-number の Context 語彙に一致する）が
//     使えない。
//
//  2. detect.go の applyCooccurrenceBoost（[rules] cooccurrence_boost）が使う
//     ±cooccurrenceWindowLines 行の近傍窓は、単なる行番号の距離でしかなく
//     「オブジェクトの境界」を知らない。そのため、たまたま数行以内に隣接する
//     別オブジェクトの高信頼 PII（例: 別ユーザーの電話番号）が、無関係な
//     弱い候補（例: 別ユーザーの氏名）まで道連れに昇格させてしまいうる。
//
// ここでは AST・専用の JSON/YAML パーサライブラリは使わず（CLAUDE.md の
// source context の方針を踏襲し、正規表現走査の対象は元の行のまま）、
// 軽量な行ベースの状態機械で各行について:
//
//   - 直近の親キー（1 段のみ。祖父母チェーンは付けない — 誤帰属リスクと
//     効果のバランスを取るための意図的なスコープ限定）を求め、
//     source_context.go の statementContext.PositiveText/NegativeText の
//     両方へ CSV/SQL 列コンテキストと同じ方式（csvColumnSignal。正負の実際の
//     判定はルール語彙側の Context/NegativeContext に委ねる）で追加する。
//   - RecordID（0 = レコード情報なし）を求め、lineContext.RecordID に設定する。
//     JSON はトップレベル直下の各オブジェクト、YAML はトップレベルキー
//     （インデント 0 の value-less な `key:`）ごとに 1 レコードとする。
//     detect.go の applyCooccurrenceBoost が、候補行とアンカー行の両方に
//     RecordID があるときは同一 RecordID を必須にし、どちらかに無いときだけ
//     従来の行窓へフォールバックする判定に使う。
//
// フル走査（sourceLineContexts）は applyObjectScopeContext が親キーと RecordID の
// 両方を求める。diff 走査（ScanDiffHunkOpts）でも、hunk 断片単体からは深さ・
// インデントのスタックを正しく復元できない（hunk の先頭がオブジェクト途中の
// ことが多く、深さ 0 からの誤った再スタートで誤帰属するリスクが高い）という
// 制約は変わらないが、呼び出し側（internal/source/gitdiff.go）が git show で
// 取得した post-image 全文を使えば、ファイル先頭から通しで親キーを再構成できる
// （CSV ヘッダを post-image から個別取得する既存の fetchCSVHeader と同じ発想）。
// applyObjectScopeContextForDiff（本ファイル下部）がこれを行う（issue #134）。
// ただし RecordID は diff 走査では一切設定しない — cooccurrence_boost 自体が
// ScanContent 専用（docs/detection-methods.md）のため、diff 側に RecordID を
// 持たせても applyCooccurrenceBoost から参照されず意味を持たない
// （detect.go の recordIDForLine のコメントを参照）。

// applyObjectScopeContext は、file が JSON/YAML であれば各行の親キー文脈と
// RecordID を ctxs へ書き込む（それ以外の拡張子では何もしない）。
// sourceKindForPath は拡張子集合を sourceKindCode 判定にしか使わないため
// （CLAUDE.md の方針どおり新しい sourceKind は追加せず、ここで sourceKindCode の
// ままサブ判定する）、.json/.yaml/.yml かどうかは objectScopeKindForPath が
// 独自に見る。
func applyObjectScopeContext(ctxs []lineContext, file string, lines []string) {
	switch objectScopeKindForPath(file) {
	case objectScopeJSON:
		parents, recordIDs := jsonObjectScope(lines)
		mergeObjectScope(ctxs, parents, recordIDs)
	case objectScopeYAML:
		parents, recordIDs := yamlObjectScope(lines)
		mergeObjectScope(ctxs, parents, recordIDs)
	}
}

type objectScopeKind int

const (
	objectScopeNone objectScopeKind = iota
	objectScopeJSON
	objectScopeYAML
)

// objectScopeKindForPath は file がオブジェクトスコープ処理の対象かを返す。
// .jsonc（コメント許容の JSON5 風拡張）は対象外: `//`/`/* */` コメントの
// 内部に現れる `{`/`}`/`"` 等を無視する追加のコメント状態を持たないため、
// 誤って構造を崩す（不整合として途中で処理を打ち切る、または誤った深さで
// 親キー・RecordID を付与する）リスクがある。対象外の場合は従来どおり
// 同一行の key=value 抽出（baseSourceLineContexts）のみが効く安全側。
func objectScopeKindForPath(file string) objectScopeKind {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".json":
		return objectScopeJSON
	case ".yaml", ".yml":
		return objectScopeYAML
	}
	return objectScopeNone
}

// IsObjectScopePath は path がオブジェクトスコープ処理の対象（.json/.yaml/.yml）
// かを返す。internal/source/gitdiff.go が diff hunk 用の post-image 全文を
// `git show` で取得するかどうかの判定に使う（取得は対象拡張子だけに意味があり、
// それ以外の拡張子で無駄な git 呼び出しをしないため）。csv_context.go の
// IsCSVOrTSVPath と対称で、拡張子リストを再定義せず objectScopeKindForPath に
// 委譲する。
func IsObjectScopePath(path string) bool {
	return objectScopeKindForPath(path) != objectScopeNone
}

// mergeObjectScope は parents/recordIDs（lines と同じ添字、jsonObjectScope /
// yamlObjectScope の戻り値）を ctxs へ反映する。RecordID は無条件に設定する
// （その行に statementContext が 1 つも無くても、cooccurrence_boost はどのみち
// Finding.Line からこの RecordID を参照するだけなので独立に意味を持つ）。
// 親キーのテキストは、既存の statementContext（同一行の key=value 抽出。
// 日本語キーはトークン化できず自己文脈を持たない行もある）が既にある場合のみ
// PositiveText/NegativeText へ追記する（真新しい statementContext を発明しない
// 安全側 — 値の範囲を親キー側の情報だけから決め打ちしない）。
func mergeObjectScope(ctxs []lineContext, parents []string, recordIDs []int) {
	for i := range ctxs {
		if i < len(recordIDs) {
			ctxs[i].RecordID = recordIDs[i]
		}
		if i < len(parents) {
			mergeParentKeyIntoStatements(ctxs[i].Statements, parents[i])
		}
	}
}

// mergeParentKeyIntoStatements は parentKey（空なら何もしない）を
// csvColumnSignal（csv_context.go）で正負文脈へ変換し、stmts の各 statement
// （同一行の key=value 抽出由来。既存 statement が 1 つもない行には何も
// 発明しない安全側 — 値の範囲を親キー側の情報だけから決め打ちしない）へ
// 追記する。ASCII ラベルは identifier トークン化、日本語等の非 ASCII ラベルは
// 本文をそのまま PositiveText に使う（matchingContexts の部分一致で照合できる）
// という、CSV ヘッダ・SQL 列名とまったく同じ変換。正負の実際の判定はルール
// 語彙（Context/NegativeContext）に委ねる。
//
// mergeObjectScope（フル走査、RecordID も設定）と applyObjectScopeContextForDiff
// （diff、RecordID は設定しない）の共通部分。
func mergeParentKeyIntoStatements(stmts []statementContext, parentKey string) {
	if parentKey == "" {
		return
	}
	positive, negative, ok := csvColumnSignal(parentKey)
	if !ok {
		return
	}
	for j := range stmts {
		st := &stmts[j]
		st.PositiveText = joinContextText(st.PositiveText, positive)
		st.NegativeText = joinContextText(st.NegativeText, negative)
	}
}

// applyObjectScopeContextForDiff は diff hunk 版の applyObjectScopeContext
// （issue #134）。hunk 自体（文脈行＋追加行の断片）は、ファイル冒頭からの
// 相対位置を持たないため単体では深さ・インデントのスタックを復元できないが
// （本ファイル冒頭のコメント参照）、呼び出し側（internal/source/gitdiff.go）が
// git show で取得した postImage（対象ファイルの post-image 全文）があれば、
// ファイル先頭から通しで親キー列を再構成し、hunk 側の行へ写像できる。
//
// hunkStartLine は hunk の新ファイル側開始行（unified diff の
// `@@ -a,b +c,d @@` の c、1 始まり）。hunkLines[i]（0 始まり）は postImage の
// 行 postLines[hunkStartLine+i-1]（0 始まり）に対応する。postImage が空文字列
// （呼び出し側の取得失敗・サイズ上限超過・バイナリ・対象拡張子でない等）、または
// hunkStartLine が 1 未満（未設定のゼロ値を含む）の場合は何もしない（安全側 =
// 親キー文脈なしの従来どおりのフォールバック）。
//
// 安全弁: 対応する postImage 側の行テキストが hunkLines 側の行テキストと
// 一致しない場合（呼び出し側の取得ずれ・作業ツリーと index の乖離など、diff
// 生成時点と post-image 取得時点の間でファイルが変化した場合等）、その行以降は
// 一切マージしない。誤ったオフセットのまま先へ進むと、無関係な行の親キー
// 文脈を誤って値へ付与しかねないため、1 行でも対応が崩れた時点で安全側に
// 倒す（jsonObjectScope の broken フラグと同じ「不整合を検出したらそこで打ち切る」
// 方針）。RecordID は付与しない（本ファイル冒頭のコメント参照。cooccurrence_boost
// は ScanContent 専用のため diff 側では意味を持たない）。
func applyObjectScopeContextForDiff(ctxs []lineContext, file string, hunkLines []string, postImage string, hunkStartLine int) {
	if postImage == "" || hunkStartLine < 1 {
		return
	}
	kind := objectScopeKindForPath(file)
	if kind == objectScopeNone {
		return
	}
	var postLines []string
	for line := range strings.SplitSeq(postImage, "\n") {
		postLines = append(postLines, strings.TrimSuffix(line, "\r"))
	}
	var parents []string
	switch kind {
	case objectScopeJSON:
		parents, _ = jsonObjectScope(postLines)
	case objectScopeYAML:
		parents, _ = yamlObjectScope(postLines)
	}
	for i := range hunkLines {
		postIdx := hunkStartLine + i - 1
		if postIdx < 0 || postIdx >= len(postLines) || postLines[postIdx] != hunkLines[i] {
			// 対応する postImage 側の行が存在しない、またはテキストが食い違う:
			// これ以降は行の対応関係を信頼できないため打ち切る。
			return
		}
		if i >= len(ctxs) {
			return
		}
		mergeParentKeyIntoStatements(ctxs[i].Statements, parents[postIdx])
	}
}

func joinContextText(existing, add string) string {
	switch {
	case add == "":
		return existing
	case existing == "":
		return add
	default:
		return existing + " " + add
	}
}

// --- JSON ---
//
// jsonScanState は 1 ファイル分の走査状態（行をまたいで持ち越す）。ブレース・
// ブラケットの深さスタック（frames）だけで追跡し、AST は組み立てない。
//
// レコード判定: 「トップレベル直下の各オブジェクト」を frames のスタック
// サイズで判定する。frames が空の状態（サイズ 0）から最初に push される
// コンテナ（配列 `[` でもオブジェクト `{` でも）が「トップレベルの入れ物」
// そのもの（トップレベル配列の `[` や、単一オブジェクトのラッパー `{`）で、
// これ自体はレコードではない。frames のサイズが 1（＝トップレベルの入れ物の
// 直下）の状態から push される `{` だけが新しいレコードを開始する。これにより
// `[{...}, {...}]`（配列の要素）と `{"a": {...}, "b": {...}}`
// （トップレベルオブジェクトの直下の値）の両方の「行指向データの並び」を
// 一貫して扱える。一方、単一レコードをネストしたサブオブジェクトで表現する
// ファイル（`{"name": ..., "phone": {"home": ...}}` のような、配列でも
// map-of-records でもない単一オブジェクト）では、"phone" サブオブジェクトが
// 独立した別レコード扱いになる既知の限界がある（トップレベル直下という
// 単純な規則の意図的なトレードオフ）。
type jsonFrame struct {
	kind      byte // '{' または '['
	parentKey string
	recordID  int
}

type jsonScanState struct {
	frames       []jsonFrame
	nextRecordID int
	awaitingKey  string
	quote        byte
	quoteStart   int
	escaped      bool
	broken       bool
}

// jsonObjectScope は lines（ファイル全行、フル走査限定）を先頭から走査し、
// 各行の親キー（1 段のみ）と RecordID を求める。パース不能・スタックの
// 不整合（対応しない閉じ括弧、閉じすぎ等）を検出した時点でその行以降は
// 一切付与しない（安全側。CLAUDE.md の csv_context.go 等と同じ方針）。
func jsonObjectScope(lines []string) (parents []string, recordIDs []int) {
	parents = make([]string, len(lines))
	recordIDs = make([]int, len(lines))
	st := &jsonScanState{nextRecordID: 1}
	for i, raw := range lines {
		if st.broken {
			break
		}
		line := normalize.Line(raw)
		st.scanLine(line)
		if st.quote != 0 {
			// 行末までに閉じ引用符が見つからない: JSON の文字列は物理行を
			// またげないため不整合とみなす。
			st.broken = true
		}
		if st.broken {
			break
		}
		if len(st.frames) > 0 {
			top := st.frames[len(st.frames)-1]
			parents[i] = top.parentKey
			recordIDs[i] = top.recordID
		}
	}
	return parents, recordIDs
}

// scanLine は正規化済みの 1 行を文字単位で走査し、st を更新する。
func (s *jsonScanState) scanLine(line string) {
	i, n := 0, len(line)
	for i < n {
		c := line[i]
		if s.quote != 0 {
			if s.escaped {
				s.escaped = false
				i++
				continue
			}
			if c == '\\' {
				s.escaped = true
				i++
				continue
			}
			if c == s.quote {
				content := line[s.quoteStart:i]
				s.quote = 0
				i++
				j := skipSpaces(line, i, n)
				if j < n && line[j] == ':' {
					// 文字列の直後（空白を挟んでもよい）が ':' ならキー。
					s.awaitingKey = content
					i = j + 1
				} else {
					// 値として消費された文字列。
					s.awaitingKey = ""
				}
				continue
			}
			i++
			continue
		}
		switch c {
		case '"':
			s.quote = '"'
			s.quoteStart = i + 1
			i++
		case '{', '[':
			s.pushFrame(c)
			i++
		case '}', ']':
			if !s.popFrame(c) {
				s.broken = true
				return
			}
			i++
		case ',':
			// カンマはオブジェクトのプロパティ区切り・配列要素区切りのいずれでも
			// 「直前の値が完全に消費された」ことを意味するため、スカラー値
			// （数値・true/false/null）の後に控えたままの awaitingKey を
			// ここで確実にクリアする。これが無いと、直前のキーが後続の
			// （キーを伴わない）配列要素オブジェクトへ誤って伝播しうる
			// （例: `[{"a":1}, {"b":2}]` の 2 要素目に "a" が親として
			// 漏れる）。
			s.awaitingKey = ""
			i++
		default:
			i++
		}
	}
}

func (s *jsonScanState) pushFrame(kind byte) {
	key := s.awaitingKey
	s.awaitingKey = ""
	recordID := 0
	if len(s.frames) > 0 {
		recordID = s.frames[len(s.frames)-1].recordID
	}
	if kind == '{' && len(s.frames) == 1 {
		recordID = s.nextRecordID
		s.nextRecordID++
	}
	s.frames = append(s.frames, jsonFrame{kind: kind, parentKey: key, recordID: recordID})
}

func (s *jsonScanState) popFrame(closeChar byte) bool {
	if len(s.frames) == 0 {
		return false
	}
	top := s.frames[len(s.frames)-1]
	if (closeChar == '}' && top.kind != '{') || (closeChar == ']' && top.kind != '[') {
		return false
	}
	s.frames = s.frames[:len(s.frames)-1]
	return true
}

// --- YAML ---
//
// yamlScanState はインデント幅のスタック（stack）で value-less な `key:` 行を
// 親として追跡する。JSON と異なり閉じ括弧のような明示的な終端が無いため、
// 「現在行のインデントがスタック上位以下になった」時点でポップするだけの
// 単純な規則で、不整合状態（broken 相当）は存在しない。
type yamlFrame struct {
	indent    int
	parentKey string
	recordID  int
}

type yamlScanState struct {
	stack []yamlFrame
	// flowDepth はフロー形式（`{a: 1}` / `[1, 2]`）が複数物理行にまたがって
	// いる間の残りブレース/ブラケット深さ（0 = フロー形式の外）。
	flowDepth int
	// blockScalarIndent は複数行ブロックスカラー（`key: |` / `key: >`）の
	// 本文中は「そのキー行のインデント」、非アクティブなら -1。
	blockScalarIndent int
	blockScalarRecord int
	nextRecordID      int
}

func (s *yamlScanState) currentParent() string {
	if len(s.stack) == 0 {
		return ""
	}
	return s.stack[len(s.stack)-1].parentKey
}

func (s *yamlScanState) currentRecordID() int {
	if len(s.stack) == 0 {
		return 0
	}
	return s.stack[len(s.stack)-1].recordID
}

// yamlObjectScope は lines（ファイル全行、フル走査限定）を先頭から走査し、
// 各行の親キー（1 段のみ）と RecordID を求める。フロー形式・複数行文字列・
// 配列項目（`- `）は保守的にスキップする（親を付けない）。
//
// レコード判定: インデント 0 の value-less な `key:` 行だけが新しいレコードを
// 開始する（「user1:\n  name: ...」のような map-of-records 形）。インデント 0
// でも値が同じ行にある葉ノード（`id: 123` のようなフラットなトップレベル
// キー）はレコードを開始しない — もし全てのインデント 0 キーがそれぞれ
// 独立の新規レコードになると、`id: 123 / name: ... / phone: ...` のような
// フラットな単一レコードの YAML（兄弟キーがそのまま同じ実体を表す、
// 最もよくある形）が各キーごとに別レコードへ分断され、cooccurrence_boost が
// 同一実体内の共起さえ検出できなくなってしまう（既存の ±5 行窓より悪化する）。
// この分断を避けるため、ネストする子を持ちうる value-less キーだけを
// レコード境界として扱う。
func yamlObjectScope(lines []string) (parents []string, recordIDs []int) {
	parents = make([]string, len(lines))
	recordIDs = make([]int, len(lines))
	st := &yamlScanState{blockScalarIndent: -1, nextRecordID: 1}
	for i, raw := range lines {
		line := normalize.Line(raw)
		trimmed := strings.TrimSpace(line)

		if st.blockScalarIndent >= 0 {
			if trimmed == "" || yamlIndent(line) > st.blockScalarIndent {
				// ブロックスカラー本文（不透明なテキスト）。親は付けないが、
				// RecordID は開始時に囲んでいたレコードを引き継ぐ。
				recordIDs[i] = st.blockScalarRecord
				continue
			}
			st.blockScalarIndent = -1
			// フォールスルーして通常行として処理する。
		}

		if st.flowDepth > 0 {
			// フロー形式（`{`/`[`）が複数物理行にまたがっている継続行。
			// 親は付けないが RecordID は現在のスコープを引き継ぐ。
			recordIDs[i] = st.currentRecordID()
			st.flowDepth = yamlFlowDepthDelta(line, st.flowDepth)
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			recordIDs[i] = st.currentRecordID()
			continue
		}

		indent := yamlIndent(line)
		for len(st.stack) > 0 && st.stack[len(st.stack)-1].indent >= indent {
			st.stack = st.stack[:len(st.stack)-1]
		}
		recordIDs[i] = st.currentRecordID()

		if trimmed == "-" || strings.HasPrefix(trimmed, "- ") {
			// 配列項目は保守的にスキップする（親を付けない・新しいフレームも
			// 積まない）。parents[i] は付与しない（ゼロ値の "" のまま）。
			// RecordID は上で設定済みで、この配列項目より外側のスコープを
			// そのまま引き継ぐ（誤帰属より「親なし相当」を優先する安全側）。
			continue
		}

		// 配列項目ではない通常の行だけ、親キーを反映する（配列項目より前に
		// 判定すると、配列項目自身にも外側の親が付いてしまい「親を付けない」
		// 方針に反するため、ここまで遅延させる）。
		parents[i] = st.currentParent()

		if _, isBlock := yamlBlockScalarKey(trimmed); isBlock {
			// ブロックスカラーのキー自体は新しいフレームを積まない
			// （本文はキー・値構造を持たない不透明なテキストのため）。
			st.blockScalarIndent = indent
			st.blockScalarRecord = recordIDs[i]
			continue
		}

		if key, ok := yamlValuelessKey(trimmed); ok {
			recordID := recordIDs[i]
			if indent == 0 {
				recordID = st.nextRecordID
				st.nextRecordID++
			}
			st.stack = append(st.stack, yamlFrame{indent: indent, parentKey: key, recordID: recordID})
			continue
		}

		// フロー形式値が複数行にまたがって開始するケース（`key: {` のように
		// 行末までに閉じない）を検出する。単一行で閉じるフロー値
		// （`key: {a: 1}`）は delta が 0 になるため対象外（従来どおり同一行の
		// key=value 抽出に委ねる）。
		if d := yamlFlowDepthDelta(line, 0); d > 0 {
			st.flowDepth = d
		}
	}
	return parents, recordIDs
}

func yamlIndent(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// yamlValuelessKey は trimmed（前後空白除去済みの 1 行）が値を伴わない
// `key:` 行かを返す。source_context.go の sourceKeyOnlyTokens と同じ
// 「":" で終わる」だけの単純な判定（引用符付きキー内の ":" 等は考慮しない）。
func yamlValuelessKey(trimmed string) (string, bool) {
	if !strings.HasSuffix(trimmed, ":") {
		return "", false
	}
	key := strings.TrimSpace(strings.TrimSuffix(trimmed, ":"))
	if key == "" {
		return "", false
	}
	return key, true
}

// yamlBlockScalarRe は `key: |`・`key: >` とチョンピング指示子（`-`/`+`）・
// 明示的インデント指示子（1〜9）の組み合わせ（順不同）を許容する。
var yamlBlockScalarRe = regexp.MustCompile(`^(.+?):\s*[|>][+\-0-9]*\s*$`)

func yamlBlockScalarKey(trimmed string) (string, bool) {
	m := yamlBlockScalarRe.FindStringSubmatch(trimmed)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

// yamlFlowDepthDelta は line 内の '{'/'[' と '}'/']' の個数差分を startDepth に
// 加えて返す（0 未満にはならない）。単純な引用符トグルで文字列内の括弧を
// 除外する（YAML の `”` エスケープの内部を厳密には解釈しないが、フロー値の
// 継続行検出という用途では「行をまたぐ開閉の有無」が分かれば十分で、
// 誤差があっても安全側＝親を付けない方向にしか影響しない）。
func yamlFlowDepthDelta(line string, startDepth int) int {
	depth := startDepth
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}
