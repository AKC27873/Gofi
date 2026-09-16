package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Baseline struct {
	mu sync.Mutex

	Created   time.Time       `json:"created"`
	Updated   time.Time       `json:"updated"`
	Hostname  string          `json:"hostname"`
	Ports     map[string]bool `json:"ports"`
	Processes map[string]bool `json:"processes"`
	Remotes   map[string]bool `json:"remotes"`

	path    string
	learn   bool
	dirty   bool
	enabled bool
}

func NewBaseline() *Baseline {
	host, _ := os.Hostname()
	return &Baseline{
		Created:   time.Now(),
		Hostname:  host,
		Ports:     map[string]bool{},
		Processes: map[string]bool{},
		Remotes:   map[string]bool{},
		enabled:   true,
	}
}

func DefaultBaselinePath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "gofi", "baseline.json")
	}
	return "gofi-baseline.json"
}

func LoadBaseLine(path string, learn bool) (*Baseline, bool, error) {
	b := NewBaseline()
	b.path = path
	b.learn = learn

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			b.learn = true
			b.dirty = true
			return b, false, nil
		}
		return b, false, err
	}
	var loaded Baseline

	if err := json.Unmarshal(data, &loaded); err != nil {
		return b, false, nil
	}
	b.Created = loaded.Created
	b.Updated = loaded.Updated
	if loaded.Ports != nil {
		b.Ports = loaded.Ports
	}
	if loaded.Processes != nil {
		b.Processes = loaded.Processes
	}
	if loaded.Remotes != nil {
		b.Remotes = loaded.Remotes
	}
	return b, true, nil
}

func DisabledBaseline() *Baseline {
	b := NewBaseline()
	b.enabled = false
	return b
}

func (b *Baseline) Learning() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.learn
}

func (b *Baseline) StopLearning() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.learn = false
}

func (b *Baseline) observe(set map[string]bool, key string) bool {
	if b == nil || !b.enabled || key == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if set[key] {
		return false
	}
	set[key] = true
	b.dirty = true
	b.Updated = time.Now()
	return !b.learn
}

func (b *Baseline) ObservePort(key string) bool {
	if b == nil {
		return false
	}
	return b.observe(b.Ports, key)
}

func (b *Baseline) ObserveProcess(name string) bool {
	if b == nil {
		return false
	}
	return b.observe(b.Processes, name)
}

func (b *Baseline) ObserveRemote(ip string) bool {
	if b == nil {
		return false
	}
	return b.observe(b.Processes, ip)
}

func (b *Baseline) Save() error {
	if b == nil || b.path == "" {
		return nil
	}
	b.mu.Lock()
	if !b.dirty {
		b.mu.Unlock()
		return nil
	}
	data, err := json.MarshalIndent(b, "", " ")
	b.dirty = false
	path := b.path
	b.mu.Unlock()
	if err != nil {
		return err
	}
}
