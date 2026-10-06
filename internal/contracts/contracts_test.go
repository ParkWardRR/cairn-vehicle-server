package contracts

import (
	"os"
	"path/filepath"
	"testing"
)

func mkdirs(t *testing.T, root string, rel ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(append([]string{root}, rel...)...), 0o755); err != nil {
		t.Fatal(err)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestTheEnvironmentOverrideWinsOverAnythingFound(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "contracts", "format")
	chdir(t, root)
	t.Setenv(EnvVar, "/somewhere/else")
	if got := Dir(); got != "/somewhere/else" {
		t.Fatalf("Dir() = %q, want the override", got)
	}
}

func TestAContractsDirectoryInAnAncestorIsFound(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "contracts", "format")
	mkdirs(t, root, "server", "internal", "x")
	t.Setenv(EnvVar, "")
	chdir(t, filepath.Join(root, "server", "internal", "x"))
	want, _ := filepath.EvalSymlinks(filepath.Join(root, "contracts"))
	got, _ := filepath.EvalSymlinks(Dir())
	if got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestAFetchedCopyIsFoundWhenThereIsNoLocalOne(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, ".contracts", "contracts", "format")
	mkdirs(t, root, "internal", "y")
	t.Setenv(EnvVar, "")
	chdir(t, filepath.Join(root, "internal", "y"))
	want, _ := filepath.EvalSymlinks(filepath.Join(root, ".contracts", "contracts"))
	got, _ := filepath.EvalSymlinks(Dir())
	if got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestADirectoryThatLacksFormatIsNotTheContractsDirectory(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "contracts") // empty: a stray folder named contracts
	t.Setenv(EnvVar, "")
	chdir(t, root)
	got, _ := filepath.EvalSymlinks(Dir())
	stray, _ := filepath.EvalSymlinks(filepath.Join(root, "contracts"))
	if got == stray {
		t.Fatal("an unrelated directory called contracts was taken for the contracts directory")
	}
}

func TestVectorsPath(t *testing.T) {
	t.Setenv(EnvVar, "/c")
	if got := Vectors("format", "v3"); got != "/c/format/v3/vectors" {
		t.Fatalf("Vectors = %q", got)
	}
}
