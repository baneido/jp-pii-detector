#!/usr/bin/env python3
"""jp-pii-detect の外部レコグナイザ・プロトコル v1 の最小デモ実装。

固定の 1 語（"サンプル太郎"）をハードコードした辞書として持ち、走査対象テキストに
それが出現した箇所だけを person-name-external として返すだけの数行のデモ。実運用では
GiNZA/BERT 等の NER モデルの推論結果をこのプロトコルへ変換して返す（このスクリプトは
その接続点の形だけを示す最小実装で、辞書検出そのものに実用性はない）。

プロトコル仕様は docs/detection-methods.md の「4.8 外部レコグナイザ連携」、
実装は internal/external のパッケージコメントを参照。

使い方（.jp-pii.toml）::

    [external_recognizer]
    command = ["python3", "integrations/external-recognizer/demo_recognizer.py"]
"""

import json
import sys

# デモ用の固定辞書（実運用では NER モデルの出力に置き換える）。
DEMO_NAMES = ["サンプル太郎"]


def find_candidates(text):
    """text 中の DEMO_NAMES の出現位置を (line, column, length) で返す（すべて 1 始まり・
    ルーン＝Unicode コードポイント単位。Python の str はコードポイント列なので、
    len()/find() の結果がそのままプロトコルの座標系になる）。"""
    for name in DEMO_NAMES:
        start = 0
        while True:
            idx = text.find(name, start)
            if idx < 0:
                break
            line_start = text.rfind("\n", 0, idx) + 1
            line_no = text.count("\n", 0, idx) + 1
            column = idx - line_start + 1
            yield line_no, column, len(name)
            start = idx + len(name)


def main():
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            req = json.loads(raw_line)
        except ValueError:
            # 壊れたリクエスト行は読み飛ばす（親側の書き込みバグ等の防御。
            # プロトコル上は親→子の形式違反は想定していないが、デモとして安全側に倒す）。
            continue
        text = req.get("text", "")
        file = req.get("file", "")
        for line_no, column, length in find_candidates(text):
            resp = {
                "file": file,
                "rule_id": "person-name-external",
                "line": line_no,
                "column": column,
                "length": length,
                "confidence": "medium",
            }
            print(json.dumps(resp, ensure_ascii=False))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
