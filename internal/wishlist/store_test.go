package wishlist

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoreValidatesAndWritesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wanted.txt")
	if err := os.WriteFile(path, []byte("Alpha\nalpha\nbeta-name\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	store := New(path)
	models, repeated, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || len(repeated) != 1 || repeated[0] != "alpha" {
		t.Fatalf("unexpected read: models=%v repeated=%v", models, repeated)
	}
	if _, err := store.Add([]string{"../escape"}); err == nil {
		t.Fatal("path traversal was accepted")
	}
	if _, err := store.Add([]string{"<script>"}); err == nil {
		t.Fatal("HTML payload was accepted")
	}
}

func TestConcurrentAddsDoNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wanted.txt")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	store := New(path)
	var wait sync.WaitGroup
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			name := "model_" + string(rune('a'+index))
			if _, err := store.Add([]string{name}); err != nil {
				t.Errorf("add %s: %v", name, err)
			}
		}(i)
	}
	wait.Wait()
	models, _, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 20 {
		t.Fatalf("got %d models, want 20", len(models))
	}
}
