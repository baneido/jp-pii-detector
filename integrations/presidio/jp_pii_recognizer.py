"""jp-pii-detect を Microsoft Presidio のカスタム Recognizer として組み込むアダプタ。

Go 製の日本特化 PII 検出器 jp-pii-detect を `scan --stdin --format json` で
サブプロセス呼び出しし、その findings を Presidio の ``RecognizerResult`` へ変換する。

Presidio は「1 本のテキスト文字列」を「文字オフセット（start/end）」基準で扱う。
jp-pii-detect 本来の出力は行・列（ファイル単位）だが、``scan --stdin`` は入力を
1 本のテキストとして走査し、各 finding にテキスト先頭からのルーン単位オフセット
``offset`` / ``end_offset``（半開区間）を付与する。Python の文字列インデックスは
コードポイント単位なので、この値をそのまま ``RecognizerResult`` の start/end に使える。

使い方::

    from presidio_analyzer import AnalyzerEngine
    from jp_pii_recognizer import JpPiiRecognizer

    analyzer = AnalyzerEngine()
    analyzer.registry.add_recognizer(JpPiiRecognizer())
    results = analyzer.analyze(text="電話: 03-1234-5678", language="ja")
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from presidio_analyzer import EntityRecognizer, RecognizerResult

try:  # nlp_artifacts の型ヒント用（実行時には未使用でも動く）
    from presidio_analyzer.nlp_engine import NlpArtifacts
except Exception:  # pragma: no cover - import 経路の差異を吸収
    NlpArtifacts = object  # type: ignore


# jp-pii-detect の rule_id → Presidio エンティティ型の既定マッピング。
# 標準型（PERSON / PHONE_NUMBER 等）に対応するものはそれへ、日本固有で対応する
# 標準型が無いものは JP_* のカスタム型に割り当てる。必要に応じて差し替え可能。
DEFAULT_ENTITY_MAP: Dict[str, str] = {
    "jp-my-number": "JP_MY_NUMBER",
    "jp-phone-number": "PHONE_NUMBER",
    "jp-postal-code": "JP_POSTAL_CODE",
    "jp-address": "LOCATION",
    "jp-address-high-recall": "LOCATION",
    "email-address": "EMAIL_ADDRESS",
    "credit-card": "CREDIT_CARD",
    "jp-drivers-license": "JP_DRIVERS_LICENSE",
    "jp-passport": "JP_PASSPORT",
    "jp-pension-number": "JP_PENSION_NUMBER",
    "jp-residence-card": "JP_RESIDENCE_CARD",
    "jp-bank-account": "JP_BANK_ACCOUNT",
    "jp-health-insurance": "JP_HEALTH_INSURANCE",
    "person-name": "PERSON",
    "person-name-high-recall": "PERSON",
    "jp-birthdate": "DATE_TIME",
}

# 信頼度（low/medium/high）→ Presidio スコア（0.0〜1.0）の既定マッピング。
DEFAULT_SCORE_MAP: Dict[str, float] = {
    "low": 0.4,
    "medium": 0.6,
    "high": 0.85,
}


class JpPiiRecognizer(EntityRecognizer):
    """jp-pii-detect バイナリを呼び出す Presidio Recognizer。

    Args:
        binary_path: jp-pii-detect 実行ファイルのパス（PATH 上なら名前だけで可）。
        min_confidence: 報告する最小信頼度（low|medium|high）。``--min-confidence``。
        high_recall: 再現率重視ルールを有効化する（``--high-recall``）。偽陽性が増える。
        config_path: 明示する .jp-pii.toml のパス。None なら jp-pii-detect が
            カレントディレクトリから上方探索する（cwd 依存になる点に注意）。
        timeout: サブプロセスのタイムアウト秒。
        entity_map: rule_id → エンティティ型の差し替え（既定は DEFAULT_ENTITY_MAP）。
        score_map: 信頼度 → スコアの差し替え（既定は DEFAULT_SCORE_MAP）。
        supported_language: 対応言語（既定 "ja"）。
        name: Recognizer 名。
    """

    def __init__(
        self,
        binary_path: str = "jp-pii-detect",
        min_confidence: str = "medium",
        high_recall: bool = False,
        config_path: Optional[str] = None,
        timeout: float = 30.0,
        entity_map: Optional[Dict[str, str]] = None,
        score_map: Optional[Dict[str, float]] = None,
        supported_language: str = "ja",
        name: str = "JpPiiRecognizer",
    ) -> None:
        self._binary = binary_path
        self._min_confidence = min_confidence
        self._high_recall = high_recall
        self._config_path = config_path
        self._timeout = timeout
        self._entity_map = dict(DEFAULT_ENTITY_MAP if entity_map is None else entity_map)
        self._score_map = dict(DEFAULT_SCORE_MAP if score_map is None else score_map)
        # サポートするエンティティ型はマッピングの値（重複排除）から導出する。
        supported_entities = sorted(set(self._entity_map.values()))
        super().__init__(
            supported_entities=supported_entities,
            supported_language=supported_language,
            name=name,
        )

    def load(self) -> None:
        """バイナリの存在を検証する（サブプロセス方式なので事前ロードは不要）。"""
        if shutil.which(self._binary) is None and not os.path.exists(self._binary):
            raise FileNotFoundError(
                f"jp-pii-detect が見つかりません: {self._binary!r}. "
                "binary_path を指定するか PATH を通してください。"
            )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: "Optional[NlpArtifacts]" = None,
    ) -> List[RecognizerResult]:
        """text を jp-pii-detect で走査し、RecognizerResult のリストを返す。

        nlp_artifacts（spaCy 等の解析結果）は jp-pii-detect が自前のルールで
        検出するため使用しない。
        """
        if not text:
            return []

        results: List[RecognizerResult] = []
        for f in self._scan(text):
            entity = self._entity_map.get(f.get("rule_id", ""))
            if entity is None:
                continue
            # Presidio から要求されたエンティティ型のみ返す（指定がなければ全件）。
            if entities and entity not in entities:
                continue
            start, end = f.get("offset"), f.get("end_offset")
            if start is None or end is None:
                # offset は --stdin 走査でのみ付与される。無ければスキップ。
                continue
            try:
                start, end = int(start), int(end)
                score = float(self._score_map.get(f.get("confidence", ""), 0.5))
            except (TypeError, ValueError) as e:
                # 出力契約違反（offset 等が非数値）を制御された失敗に変換する。
                # 生値（match）は漏らさないよう rule_id だけを示す。
                raise RuntimeError(
                    "jp-pii-detect の finding に不正な数値（offset/end_offset/"
                    f"confidence）が含まれます: rule_id={f.get('rule_id', '')!r}"
                ) from e
            results.append(
                RecognizerResult(
                    entity_type=entity,
                    start=start,
                    end=end,
                    score=score,
                    analysis_explanation=None,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                        # 元の rule_id を残しておくと後段でのデバッグに役立つ。
                        "jp_pii_rule_id": f.get("rule_id", ""),
                    },
                )
            )
        return results

    def _scan(self, text: str) -> List[dict]:
        """jp-pii-detect scan --stdin を実行し、findings 配列を返す。"""
        cmd = [
            self._binary,
            "scan",
            "--stdin",
            "--format",
            "json",
            "--unmask",  # オフセット計算と後段の匿名化のため生値が必要
            "--min-confidence",
            self._min_confidence,
        ]
        if self._high_recall:
            cmd.append("--high-recall")
        if self._config_path:
            cmd += ["--config", self._config_path]

        try:
            proc = subprocess.run(
                cmd,
                input=text,
                capture_output=True,
                encoding="utf-8",
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"jp-pii-detect がタイムアウトしました（{self._timeout}s）"
            ) from e
        except OSError as e:
            # バイナリ不在（FileNotFoundError）や実行権限なし（PermissionError）など、
            # サブプロセス起動失敗をまとめて分かりやすいメッセージへ変換する。
            raise RuntimeError(
                f"jp-pii-detect を起動できません: {self._binary!r}: {e}. "
                "binary_path・PATH・実行権限を確認してください。"
            ) from e

        # 終了コード: 0=検出なし, 1=検出あり, 2=エラー。
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"jp-pii-detect が失敗しました (exit {proc.returncode}): "
                f"{proc.stderr.strip()}"
            )
        out = proc.stdout.strip()
        if not out:
            return []
        try:
            doc = json.loads(out)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"jp-pii-detect の出力を JSON として解釈できませんでした: {e}"
            ) from e
        if not isinstance(doc, dict):
            raise RuntimeError(
                "jp-pii-detect の出力が JSON オブジェクトではありません: "
                f"{type(doc).__name__}"
            )
        findings = doc.get("findings", [])
        if not isinstance(findings, list):
            raise RuntimeError(
                "jp-pii-detect の出力 findings が配列ではありません: "
                f"{type(findings).__name__}"
            )
        return findings
