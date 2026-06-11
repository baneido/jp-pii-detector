package source

import (
	"reflect"
	"testing"
)

func TestParseDiff(t *testing.T) {
	diff := `diff --git a/users.csv b/users.csv
index 1111111..2222222 100644
--- a/users.csv
+++ b/users.csv
@@ -3,0 +4,2 @@ header
+TEL: 090-1234-5678
+name,age
diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-removed line
diff --git a/docs/memo.md b/docs/memo.md
--- a/docs/memo.md
+++ b/docs/memo.md
@@ -9,0 +10 @@
+〒150-0043
`
	got := ParseDiff(diff)
	want := []AddedLine{
		{File: "users.csv", Line: 4, Text: "TEL: 090-1234-5678"},
		{File: "users.csv", Line: 5, Text: "name,age"},
		{File: "docs/memo.md", Line: 10, Text: "〒150-0043"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDiff = %+v, want %+v", got, want)
	}
}

func TestParseDiffBinaryAndEmpty(t *testing.T) {
	if got := ParseDiff("Binary files a/img.png and b/img.png differ\n"); len(got) != 0 {
		t.Errorf("ParseDiff(binary) = %+v, want empty", got)
	}
	if got := ParseDiff(""); len(got) != 0 {
		t.Errorf("ParseDiff(empty) = %+v, want empty", got)
	}
}
