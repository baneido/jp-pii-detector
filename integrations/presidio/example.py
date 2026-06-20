"""jp-pii-detect を Presidio に組み込んで「検出 → 匿名化」する最小デモ。

前提:
  - jp-pii-detect がビルド済みで PATH 上にある、または環境変数 JP_PII_DETECT_BIN
    で実行ファイルのパスを指定している。
  - presidio-analyzer / presidio-anonymizer がインストール済み（requirements.txt）。

実行:
  python example.py

NLP モデル（spaCy ja_core_news_sm）が入っていれば AnalyzerEngine 経由で実行し、
無ければ Recognizer を直接呼ぶ経路にフォールバックする（どちらも結果は同じ。
jp-pii-detect は NLP に依存しないため）。最後に AnonymizerEngine で匿名化する。
"""

from __future__ import annotations

import os

from presidio_anonymizer import AnonymizerEngine

from jp_pii_recognizer import JpPiiRecognizer

# 走査対象のサンプル（実在しない架空の値）。
SAMPLE_TEXT = (
    "お客様情報\n"
    "氏名: 山田太郎\n"
    "電話番号: 03-1234-5678\n"
    "携帯: 090-1234-5678\n"
    "郵便番号: 100-0001\n"
    "住所: 東京都千代田区千代田1-1\n"
    "メール: taro.yamada@kaisha.co.jp\n"
    "誕生日: 1985年4月1日\n"
)


def build_recognizer() -> JpPiiRecognizer:
    recognizer = JpPiiRecognizer(
        binary_path=os.environ.get("JP_PII_DETECT_BIN", "jp-pii-detect"),
        min_confidence="medium",
    )
    recognizer.load()  # バイナリの存在を先に確認（無ければ FileNotFoundError）
    return recognizer


def analyze(recognizer: JpPiiRecognizer, text: str):
    """spaCy ja モデルがあれば AnalyzerEngine 経由、無ければ Recognizer を直接呼ぶ。"""
    if _has_spacy_ja():
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "ja", "model_name": "ja_core_news_sm"}],
            }
        ).create_engine()
        # registry の対応言語も "ja" に揃える（既定は ["en"] で AnalyzerEngine と不整合になる）。
        registry = RecognizerRegistry(supported_languages=["ja"])
        registry.add_recognizer(recognizer)
        analyzer = AnalyzerEngine(
            registry=registry, nlp_engine=nlp_engine, supported_languages=["ja"]
        )
        print("[AnalyzerEngine 経由（spaCy ja）]")
        return analyzer.analyze(text=text, language="ja")

    # spaCy モデルが無い環境向けフォールバック: Recognizer を直接呼ぶ。
    # AnalyzerEngine は NLP パイプラインを必要とするが、jp-pii-detect は NLP 非依存
    # なので、デモを動かすだけならこれで十分（本番は上の AnalyzerEngine 経路を使う）。
    print("[Recognizer 直接呼び出し（spaCy ja モデル未導入のためフォールバック）]")
    return recognizer.analyze(text=text, entities=[])


def _has_spacy_ja() -> bool:
    try:
        import spacy

        return spacy.util.is_package("ja_core_news_sm")
    except Exception:
        return False


def main() -> None:
    recognizer = build_recognizer()

    print("=== 入力 ===")
    print(SAMPLE_TEXT)

    results = sorted(analyze(recognizer, SAMPLE_TEXT), key=lambda r: r.start)

    print("=== 検出結果（Presidio RecognizerResult）===")
    for r in results:
        rule_id = (r.recognition_metadata or {}).get("jp_pii_rule_id", "")
        print(
            f"  {r.entity_type:15} score={r.score:.2f} "
            f"[{r.start}:{r.end}] {SAMPLE_TEXT[r.start:r.end]!r}  (rule={rule_id})"
        )

    anonymized = AnonymizerEngine().anonymize(text=SAMPLE_TEXT, analyzer_results=results)
    print("\n=== 匿名化後 ===")
    print(anonymized.text)


if __name__ == "__main__":
    main()
