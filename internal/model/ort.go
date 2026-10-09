//go:build cgo && ort

package model

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	ort "github.com/microsoft/onnxruntime/go/onnxruntime"
)

// ortLibraryEnv は ONNX Runtime の共有ライブラリのパスを指定する環境変数。
const ortLibraryEnv = "JP_PII_ORT_LIBRARY"

// Open は dir（model.int8.onnx・tokenizer.json・sumi_labels.json・calibrator.json を
// 置いたディレクトリ）のモデルを読み込む。ONNX Runtime の共有ライブラリは
// JP_PII_ORT_LIBRARY、dir 内の libonnxruntime.*、システムの既定の検索パスの順に探す。
func Open(dir string) (*Recognizer, error) {
	if lib := ortLibraryPath(dir); lib != "" {
		ort.SetSharedLibraryPath(lib)
	}
	if err := ort.Init(); err != nil {
		return nil, fmt.Errorf("ONNX Runtime を読み込めません（%s で共有ライブラリのパスを指定できます）: %w", ortLibraryEnv, err)
	}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, err
	}
	defer opts.Close()
	// 並列性はファイル単位（呼び出し側のワーカー）で得るので、1 回の推論は 1 スレッドにする。
	if err := opts.SetIntraOpNumThreads(1); err != nil {
		return nil, err
	}
	if err := opts.SetInterOpNumThreads(1); err != nil {
		return nil, err
	}
	sess, err := ort.NewSession(filepath.Join(dir, onnxFile), opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", onnxFile, err)
	}
	infer := func(ids []int64) ([][]float32, error) {
		n := int64(len(ids))
		mask := make([]int64, n)
		for i := range mask {
			mask[i] = 1
		}
		in, err := ort.CreateTensor([]int64{1, n}, ids)
		if err != nil {
			return nil, err
		}
		defer in.Close()
		am, err := ort.CreateTensor([]int64{1, n}, mask)
		if err != nil {
			return nil, err
		}
		defer am.Close()
		outs, err := sess.Run(context.Background(), map[string]*ort.Tensor{"input_ids": in, "attention_mask": am}, []string{"logits"})
		if err != nil {
			return nil, err
		}
		out := outs["logits"]
		defer out.Close()
		flat, err := ort.TensorData[float32](out)
		if err != nil {
			return nil, err
		}
		shape := out.Shape()
		if len(shape) != 3 || shape[1] != n {
			return nil, fmt.Errorf("logits の形 %v が想定外です", shape)
		}
		k := int(shape[2])
		rows := make([][]float32, n)
		for i := range rows {
			rows[i] = append([]float32(nil), flat[i*k:(i+1)*k]...)
		}
		return rows, nil
	}
	r, err := newRecognizer(dir, infer, sess.Close)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	return r, nil
}

func ortLibraryPath(dir string) string {
	if p := os.Getenv(ortLibraryEnv); p != "" {
		return p
	}
	name := map[string]string{"darwin": "libonnxruntime.dylib", "windows": "onnxruntime.dll"}[runtime.GOOS]
	if name == "" {
		name = "libonnxruntime.so"
	}
	if p := filepath.Join(dir, name); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
