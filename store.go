package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Address is a .onion identity: the address plus the key that owns it. It lives
// independently of any service, so deleting a service never loses the address.
type Address struct {
	ID        string    `json:"id"`
	OnionID   string    `json:"onion_id"` // 56 chars, no ".onion"
	PrivKey   string    `json:"priv_key"` // ED25519-V3:<base64>
	Label     string    `json:"label"`
	Source    string    `json:"source"` // service | vanity | legacy
	Vanity    string    `json:"vanity"` // matched prefix, if any
	CreatedAt time.Time `json:"created_at"`
}

// Service is a routing rule bound to at most one Address.
type Service struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AddressID string    `json:"address_id"` // "" = no address bound
	Target    string    `json:"target"`
	BasicUser string    `json:"basic_user"`
	BasicHash string    `json:"basic_hash"` // bcrypt hash for caddy http_basic
	RateLimit int       `json:"rate_limit"` // events per minute per onion, 0 = unlimited
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type state struct {
	Addresses []Address `json:"addresses"`
	Services  []Service `json:"services"`
}

// loadService also understands the pre-address-library layout, where the onion
// identity lived on the service itself.
type loadService struct {
	Service
	OnionID string `json:"onion_id"`
	PrivKey string `json:"priv_key"`
}

type loadState struct {
	Addresses []Address     `json:"addresses"`
	Services  []loadService `json:"services"`
}

// Store keeps everything in one JSON file with atomic rewrites. The dataset is
// tiny (tens of rows) so this beats pulling in a database driver.
type Store struct {
	mu   sync.Mutex
	path string
	s    state
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &Store{path: filepath.Join(dir, "services.json")}
	raw, err := os.ReadFile(st.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.s = state{}
	case err != nil:
		return nil, err
	default:
		var ls loadState
		if err := json.Unmarshal(raw, &ls); err != nil {
			return nil, err
		}
		migrated := false
		for _, svc := range ls.Services {
			s := svc.Service
			if s.AddressID == "" && svc.OnionID != "" && svc.PrivKey != "" {
				addr := Address{
					ID:        newID(),
					OnionID:   svc.OnionID,
					PrivKey:   svc.PrivKey,
					Label:     svc.Service.Name,
					Source:    "legacy",
					CreatedAt: svc.Service.CreatedAt,
				}
				ls.Addresses = append(ls.Addresses, addr)
				s.AddressID = addr.ID
				migrated = true
			}
			st.s.Services = append(st.s.Services, s)
		}
		st.s.Addresses = ls.Addresses
		if migrated {
			if err := st.flushLocked(); err != nil {
				return nil, err
			}
		}
	}
	return st, nil
}

// ---------- addresses ----------

func (s *Store) ListAddresses() []Address {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Address, len(s.s.Addresses))
	copy(out, s.s.Addresses)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) GetAddress(id string) (Address, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.s.Addresses {
		if a.ID == id {
			return a, true
		}
	}
	return Address{}, false
}

func (s *Store) PutAddress(a Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.s.Addresses {
		if s.s.Addresses[i].ID == a.ID {
			s.s.Addresses[i] = a
			return s.flushLocked()
		}
	}
	s.s.Addresses = append(s.s.Addresses, a)
	return s.flushLocked()
}

func (s *Store) DeleteAddress(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.s.Addresses {
		if s.s.Addresses[i].ID == id {
			s.s.Addresses = append(s.s.Addresses[:i], s.s.Addresses[i+1:]...)
			return s.flushLocked()
		}
	}
	return nil
}

// ---------- services ----------

func (s *Store) ListServices() []Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Service, len(s.s.Services))
	copy(out, s.s.Services)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) GetService(id string) (Service, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, svc := range s.s.Services {
		if svc.ID == id {
			return svc, true
		}
	}
	return Service{}, false
}

func (s *Store) PutService(svc Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.s.Services {
		if s.s.Services[i].ID == svc.ID {
			s.s.Services[i] = svc
			return s.flushLocked()
		}
	}
	s.s.Services = append(s.s.Services, svc)
	return s.flushLocked()
}

func (s *Store) DeleteService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.s.Services {
		if s.s.Services[i].ID == id {
			s.s.Services = append(s.s.Services[:i], s.s.Services[i+1:]...)
			return s.flushLocked()
		}
	}
	return nil
}

// ServiceUsingAddress returns the service currently bound to an address.
func (s *Store) ServiceUsingAddress(addressID string) (Service, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, svc := range s.s.Services {
		if svc.AddressID == addressID {
			return svc, true
		}
	}
	return Service{}, false
}

func (s *Store) flushLocked() error {
	buf, err := json.MarshalIndent(s.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
