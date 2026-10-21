//go:build linux && amd64

package model

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestAMXFilterJumpsStayInProgram(t *testing.T) {
	prog := amxFilter()
	if last := prog[len(prog)-1]; last.code != bpfRetK || last.k != seccompRetAllow {
		t.Fatalf("最後の命令が許可ではありません: %+v", last)
	}
	for i, ins := range prog {
		if ins.code != bpfJeqK {
			continue
		}
		for _, off := range []uint8{ins.jt, ins.jf} {
			if i+1+int(off) >= len(prog) {
				t.Fatalf("%d 番目の分岐がプログラムの外を指しています", i)
			}
		}
	}
	// 引数が ARCH_REQ_XCOMP_PERM のときだけ EPERM の命令に着く。
	if got := prog[5]; got.k != archReqXcompPerm || prog[6].k != seccompRetErrno|uint32(syscall.EPERM) {
		t.Fatalf("拒否の条件が想定と違います: %+v %+v", got, prog[6])
	}
}

// TestDisableAMXDeniesXcompPerm は子プロセスでフィルタを入れ、
// arch_prctl(ARCH_REQ_XCOMP_PERM) が EPERM になり、他のシステムコールは通ることを確かめる。
// フィルタは外せないので、テスト本体のプロセスには入れない。
func TestDisableAMXDeniesXcompPerm(t *testing.T) {
	if os.Getenv("JPD_AMX_CHILD") == "1" {
		if err := disableAMX(); err != nil {
			t.Skipf("seccomp を使えない環境です: %v", err)
		}
		const xfeatureTileData = 18
		_, _, errno := syscall.Syscall(sysArchPrctl, archReqXcompPerm, xfeatureTileData, 0)
		if errno != syscall.EPERM {
			t.Fatalf("ARCH_REQ_XCOMP_PERM が拒まれません: errno=%v", errno)
		}
		if _, err := os.Getwd(); err != nil {
			t.Fatalf("他のシステムコールまで拒まれています: %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDisableAMXDeniesXcompPerm$", "-test.v")
	cmd.Env = append(os.Environ(), "JPD_AMX_CHILD=1", amxEnv+"=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("子プロセスが失敗しました: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
