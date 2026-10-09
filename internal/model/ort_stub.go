//go:build !(cgo && ort)

package model

import "errors"

// Open は、モデル推論なしのビルドでは常にエラーを返す。
func Open(string) (*Recognizer, error) {
	return nil, errors.New("このバイナリはモデル推論なしでビルドされています（CGO_ENABLED=1 go build -tags ort でビルドしてください）")
}
