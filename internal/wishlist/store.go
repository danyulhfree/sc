package wishlist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const maxFileSize = 1 << 20

var modelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

var ErrNotFound = errors.New("model not found")

type Store struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Store { return &Store{path: path} }

func Normalize(model string) (string, error) {
	model = strings.ToLower(strings.TrimSpace(model))
	if !modelPattern.MatchString(model) {
		return "", fmt.Errorf("model must match %s", modelPattern.String())
	}
	return model, nil
}

func (s *Store) Read() ([]string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked()
}

func (s *Store) Add(models []string) ([]string, error) {
	if len(models) == 0 || len(models) > 100 {
		return nil, errors.New("provide between 1 and 100 models")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current, _, err := s.readLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seen := make(map[string]struct{}, len(current)+len(models))
	for _, model := range current {
		seen[model] = struct{}{}
	}
	added := make([]string, 0, len(models))
	for _, raw := range models {
		model, err := Normalize(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[model]; exists {
			continue
		}
		seen[model] = struct{}{}
		current = append(current, model)
		added = append(added, model)
	}
	if len(added) == 0 {
		return []string{}, nil
	}
	if err := s.writeLocked(current); err != nil {
		return nil, err
	}
	return added, nil
}

func (s *Store) Delete(raw string) error {
	model, err := Normalize(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current, _, err := s.readLocked()
	if err != nil {
		return err
	}
	result := make([]string, 0, len(current))
	found := false
	for _, item := range current {
		if item == model {
			found = true
			continue
		}
		result = append(result, item)
	}
	if !found {
		return ErrNotFound
	}
	return s.writeLocked(result)
}

func (s *Store) readLocked() ([]string, []string, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil {
		return nil, nil, err
	} else if info.Size() > maxFileSize {
		return nil, nil, fmt.Errorf("wanted file exceeds %d bytes", maxFileSize)
	}

	seen := make(map[string]struct{})
	models := make([]string, 0)
	repeated := make([]string, 0)
	scanner := bufio.NewScanner(io.LimitReader(file, maxFileSize+1))
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		model, err := Normalize(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid wanted entry %q: %w", raw, err)
		}
		if _, exists := seen[model]; exists {
			repeated = append(repeated, model)
			continue
		}
		seen[model] = struct{}{}
		models = append(models, model)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	sort.Strings(repeated)
	return models, repeated, nil
}

func (s *Store) writeLocked(models []string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wanted-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	content := ""
	if len(models) > 0 {
		content = strings.Join(models, "\n") + "\n"
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}
