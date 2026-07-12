# jp-pii-detect × Microsoft Presidio 連携

[Microsoft Presidio](https://github.com/microsoft/presidio) のカスタム Recognizer
として `jp-pii-detect`（日本特化の PII 検出器）を組み込むためのアダプタです。
Presidio の解析エンジンに日本固有のルール（マイナンバー・電話番号・郵便番号・
住所・運転免許証など）を追加し、Presidio の匿名化（Anonymizer）もそのまま使えます。

## 仕組み

Presidio は Python 製で、「1 本のテキスト文字列」を「文字オフセット（start/end）」
基準で扱います。一方 `jp-pii-detect` は Go 製で、本来はファイル/git diff を行・列
基準で走査します。この差を埋めるために 2 つを用意しています。

1. **Go 側**: `jp-pii-detect scan --stdin` … 標準入力を 1 本のテキストとして走査し、
   各検出に `offset` / `end_offset`（テキスト先頭からの**ルーン単位**の半開区間）を
   付けた JSON を出力します。Python の文字列インデックスはコードポイント単位なので、
   この値をそのまま `RecognizerResult` の start/end に使えます。ただし解析対象テキストに
   JSON の `\uXXXX` エスケープが含まれる場合は復号したビューを走査するため、
   `offset`/`end_offset` は標準入力へ渡した元テキストではなく**復号後テキスト上**の
   ルーンオフセットになります。
2. **Python 側**: `JpPiiRecognizer`（`presidio_analyzer.EntityRecognizer` の
   サブクラス）が、解析対象テキストを上記コマンドにサブプロセスで渡し、findings を
   `RecognizerResult` へ変換します。

```
Presidio AnalyzerEngine
        │  analyze(text, language="ja")
        ▼
JpPiiRecognizer.analyze()
        │  subprocess: jp-pii-detect scan --stdin --format json --unmask
        ▼
findings(JSON: rule_id, offset, end_offset, confidence)
        │  rule_id→entity / confidence→score / offset→start・end
        ▼
List[RecognizerResult]  →  AnonymizerEngine で匿名化
```

## セットアップ

```console
# 1) jp-pii-detect 本体（Go バイナリ）をビルドして PATH に通す
go build -o jp-pii-detect ./cmd/jp-pii-detect
export PATH="$PWD:$PATH"            # もしくは JP_PII_DETECT_BIN にフルパスを設定

# 2) Python 依存をインストール
cd integrations/presidio
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3) デモ実行
python example.py
```

> [!NOTE]
> クリーンな環境では、spacy の推移依存が解決しきれず import 時に
> `ModuleNotFoundError: No module named 'click'` 等で失敗することがあります。
> その場合は不足分を明示的に入れてください（例: `pip install click`）。
> AnalyzerEngine 経由（spaCy ja）を試す場合のみ `python -m spacy download ja_core_news_sm`
> も必要です（未導入なら example.py は Recognizer 直接呼び出しにフォールバック）。

`example.py` の出力イメージ（検出結果は Presidio の型、最後に匿名化後テキスト）:

```
=== 検出結果（Presidio RecognizerResult）===
  PHONE_NUMBER    score=0.85 [21:33] '03-1234-5678'  (rule=jp-phone-number)
  ...
=== 匿名化後 ===
  電話番号: <PHONE_NUMBER>
  ...
```

## 使い方（既存の AnalyzerEngine に追加する場合）

```python
from presidio_analyzer import AnalyzerEngine
from jp_pii_recognizer import JpPiiRecognizer

analyzer = AnalyzerEngine()  # 既存の構成
analyzer.registry.add_recognizer(JpPiiRecognizer())

results = analyzer.analyze(text="電話: 03-1234-5678", language="ja")
```

`JpPiiRecognizer` の主なオプション:

| 引数 | 既定 | 説明 |
|---|---|---|
| `binary_path` | `"jp-pii-detect"` | 実行ファイルのパス（PATH 上なら名前のみ） |
| `min_confidence` | `"medium"` | 報告する最小信頼度（`low\|medium\|high`） |
| `high_recall` | `False` | 再現率重視ルールを有効化（偽陽性増） |
| `config_path` | `None` | 明示する `.jp-pii.toml`（None だと cwd から上方探索） |
| `entity_map` | `DEFAULT_ENTITY_MAP` | rule_id → Presidio エンティティ型の対応 |
| `score_map` | `DEFAULT_SCORE_MAP` | 信頼度 → スコアの対応 |

## エンティティ型の対応

標準型に対応するものはそれへ、対応する標準型が無い日本固有のものは `JP_*` の
カスタム型に割り当てています（`jp_pii_recognizer.DEFAULT_ENTITY_MAP`）。

| jp-pii-detect rule_id | Presidio entity_type |
|---|---|
| `jp-my-number` | `JP_MY_NUMBER` |
| `jp-phone-number` | `PHONE_NUMBER` |
| `jp-postal-code` | `JP_POSTAL_CODE` |
| `jp-address` / `jp-address-high-recall` | `LOCATION` |
| `email-address` | `EMAIL_ADDRESS` |
| `credit-card` | `CREDIT_CARD` |
| `jp-drivers-license` | `JP_DRIVERS_LICENSE` |
| `jp-passport` | `JP_PASSPORT` |
| `jp-pension-number` | `JP_PENSION_NUMBER` |
| `jp-residence-card` | `JP_RESIDENCE_CARD` |
| `jp-bank-account` | `JP_BANK_ACCOUNT` |
| `jp-health-insurance` | `JP_HEALTH_INSURANCE` |
| `person-name` / `person-name-high-recall` | `PERSON` |
| `jp-birthdate` | `DATE_TIME` |

`entity_map` を渡せば自由に差し替えられます。

## 注意 / 制限

- **プロセス起動コスト**: テキスト 1 本ごとにバイナリを起動します。大量の短文を
  処理する場合は、`jp-pii-detect` を HTTP サービス化して `RemoteRecognizer` で
  呼ぶ方が効率的です（本アダプタはサブプロセス方式）。
- **CI 専用機能は無効**: git diff 走査・±1 行のクロスライン相関・`jp-pii-detector:ignore`
  マーカー・終了コードによるゲートは、この経路では使われません。
- **`--unmask` 前提**: オフセット計算と後段の匿名化のため生値を取得します。信頼境界内
  （ローカル/自社内）での利用を想定してください。
- **`config_path`**: 未指定だと `jp-pii-detect` がカレントディレクトリから `.jp-pii.toml`
  を上方探索するため、実行ディレクトリで挙動が変わり得ます。再現性が必要なら明示してください。
