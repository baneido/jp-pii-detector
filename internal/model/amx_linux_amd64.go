//go:build linux && amd64

package model

import (
	"os"
	"syscall"
	"unsafe"
)

// ONNX Runtime の MLAS は、x86-64 の Linux で AMX（Advanced Matrix Extensions）が
// 使えると arch_prctl(ARCH_REQ_XCOMP_PERM) で AMX のタイルを要求し、INT8 の行列積
// （U8S8 QGEMM）を AMX で計算する。ところが TILEDATA を退避・復元しない仮想マシン
// （一部の KVM ゲストなど）では、スレッドの切り替えでタイルの中身が壊れ、INT8 モデルの
// 出力が実行ごとに変わる（microsoft/onnxruntime#33247）。Sumi の INT8 モデルでは、
// コードの「os」「def」のような識別子が氏名やメールと判定される誤検知として現れる。
//
// disableAMX は ARCH_REQ_XCOMP_PERM だけを EPERM で拒む seccomp フィルタを
// プロセスの全スレッドに入れる。MLAS は要求が拒まれると AVX512-VNNI / AVX2 の経路に
// 戻るので、結果は fp32 モデルと同じく決定的になる。AMX を使わないことによる速度の
// 差は、このモデル（1 推論 254 トークン、1 スレッド）では小さい。
//
// フィルタは ONNX Runtime を読み込む前に入れる必要がある。seccomp フィルタは
// 外せないので、プロセスには no_new_privs が付く（setuid のプログラムを実行しても
// 権限が上がらない。git などの子プロセスの動作には影響しない）。
// JP_PII_ORT_AMX=1 で無効にできる（AMX の状態を正しく扱う実機やホストで速度を優先する場合）。

const amxEnv = "JP_PII_ORT_AMX"

const (
	sysArchPrctl         = 158 // x86-64
	sysSeccomp           = 317 // x86-64
	archReqXcompPerm     = 0x1023
	auditArchX8664       = 0xc000003e
	prSetNoNewPrivs      = 38
	seccompSetModeFilter = 1
	seccompFlagTsync     = 1
	seccompRetAllow      = 0x7fff0000
	seccompRetErrno      = 0x00050000

	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	// struct seccomp_data のオフセット。
	offNr    = 0
	offArch  = 4
	offArgs0 = 16 // args[0] の下位 32 ビット（リトルエンディアン）
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// amxFilter は arch_prctl(ARCH_REQ_XCOMP_PERM, ...) だけを EPERM にし、
// それ以外のシステムコールをすべて許可する BPF プログラムを返す。
func amxFilter() []sockFilter {
	return []sockFilter{
		{code: bpfLdWAbs, k: offArch},
		{code: bpfJeqK, jt: 0, jf: 5, k: auditArchX8664}, // 異なるアーキテクチャなら許可
		{code: bpfLdWAbs, k: offNr},
		{code: bpfJeqK, jt: 0, jf: 3, k: sysArchPrctl},
		{code: bpfLdWAbs, k: offArgs0},
		{code: bpfJeqK, jt: 0, jf: 1, k: archReqXcompPerm},
		{code: bpfRetK, k: seccompRetErrno | uint32(syscall.EPERM)},
		{code: bpfRetK, k: seccompRetAllow},
	}
}

// disableAMX は JP_PII_ORT_AMX=1 でない限り、AMX の要求を拒むフィルタを入れる。
// 入れられなかった（古いカーネル、すでに別の seccomp 下にあるなど）ときは error を
// 返すが、呼び出し側は警告にとどめて推論を続けてよい（AMX がなければ元から無関係）。
func disableAMX() error {
	if os.Getenv(amxEnv) == "1" {
		return nil
	}
	prog := amxFilter()
	fprog := sockFprog{len: uint16(len(prog)), filter: &prog[0]}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	if r, _, errno := syscall.RawSyscall(sysSeccomp, seccompSetModeFilter, seccompFlagTsync, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return errno
	} else if r != 0 {
		return syscall.EAGAIN // TSYNC で同期できなかったスレッドがある
	}
	return nil
}
