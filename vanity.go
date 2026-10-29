package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// Onion v3 addresses are derived, not chosen:
//
//	address  = base32(PUBKEY | CHECKSUM | VERSION)      (35 bytes -> 56 chars)
//	CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
//	VERSION  = 3
//
// Tor's ED25519-V3 private key blob is the 64-byte **expanded** key used by
// RFC 8032: the clamped scalar `a` followed by the nonce prefix. The public key
// is A = [a]B, so Go needs an edwards25519 point multiply to mint identities
// offline. Both facts are pinned by TestOnionAddressMatchesTor against an
// identity tor itself generated.
func onionAddress(pub []byte) string {
	version := byte(3)

	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pub)
	h.Write([]byte{version})
	checksum := h.Sum(nil)[:2]

	payload := make([]byte, 0, 35)
	payload = append(payload, pub...)
	payload = append(payload, checksum...)
	payload = append(payload, version)

	// Onion addresses are lowercase base32.
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(payload))
}

// newOnionIdentity derives a fresh identity: expanded secret key (a || prefix)
// plus the address it owns.
func newOnionIdentity(seed []byte) (expanded []byte, onionID string, err error) {
	h := sha512.Sum512(seed)

	exp := make([]byte, 64)
	copy(exp[:32], h[:32])
	// RFC 8032 clamping, exactly what tor expects to read back.
	exp[0] &= 248
	exp[31] &= 127
	exp[31] |= 64
	copy(exp[32:], h[32:])

	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(exp[:32])
	if err != nil {
		return nil, "", err
	}
	pub := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	return exp, onionAddress(pub), nil
}

// torKeyBlob renders an expanded key the way tor's ADD_ONION expects it.
func torKeyBlob(expanded []byte) string {
	return "ED25519-V3:" + base64.StdEncoding.EncodeToString(expanded)
}

var prefixRe = regexp.MustCompile(`^[a-z2-7]{1,7}$`)

type VanityResult struct {
	OnionID string    `json:"onion_id"`
	PrivKey string    `json:"priv_key"`
	FoundAt time.Time `json:"found_at"`
	Tested  uint64    `json:"tested"`
}

type VanityJob struct {
	ID      string
	Prefix  string
	Want    int
	Workers int

	started time.Time
	ended   time.Time
	tested  uint64

	mu    sync.Mutex
	found []VanityResult
	state string

	cancel   chan struct{}
	cancelOn sync.Once
}

func (j *VanityJob) stop(state string) {
	j.cancelOn.Do(func() {
		close(j.cancel)
		j.mu.Lock()
		if j.state == "running" {
			j.state = state
			j.ended = time.Now()
		}
		j.mu.Unlock()
	})
}

func (j *VanityJob) add(addr string, expanded []byte) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != "running" {
		return false
	}
	for _, r := range j.found {
		if r.OnionID == addr {
			return true
		}
	}
	j.found = append(j.found, VanityResult{
		OnionID: addr,
		PrivKey: torKeyBlob(expanded),
		FoundAt: time.Now(),
		Tested:  atomic.LoadUint64(&j.tested),
	})
	if len(j.found) >= j.Want {
		j.state = "done"
		j.ended = time.Now()
		j.cancelOn.Do(func() { close(j.cancel) })
	}
	return true
}

type VanityView struct {
	ID       string         `json:"id"`
	Prefix   string         `json:"prefix"`
	State    string         `json:"state"`
	Want     int            `json:"want"`
	Workers  int            `json:"workers"`
	Found    []VanityResult `json:"found"`
	Tested   uint64         `json:"tested"`
	Speed    float64        `json:"speed"` // keys per second
	ETA      float64        `json:"eta"`   // seconds, 0 when unknown
	Started  time.Time      `json:"started_at"`
	Ended    *time.Time     `json:"ended_at,omitempty"`
	Elapsed  float64        `json:"elapsed"`
	KeySpace float64        `json:"key_space"`
}

type VanityManager struct {
	mu      sync.Mutex
	jobs    map[string]*VanityJob
	order   []string
	workers int
}

func NewVanityManager(workers int) *VanityManager {
	if workers <= 0 {
		workers = defaultVanityWorkers()
	}
	return &VanityManager{jobs: map[string]*VanityJob{}, workers: workers}
}

func defaultVanityWorkers() int {
	n := numCPU() - 1
	if n < 1 {
		n = 1
	}
	if n > 12 {
		n = 12
	}
	return n
}

func (m *VanityManager) Start(prefix string, want int) (*VanityView, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	prefix = strings.TrimPrefix(prefix, ".")
	prefix = strings.TrimSuffix(prefix, ".onion")
	if !prefixRe.MatchString(prefix) {
		return nil, errors.New("前缀只能是 a-z 与 2-7，1~7 位（如 ab、777、shop）")
	}
	if want < 1 {
		want = 1
	}
	if want > 20 {
		want = 20
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.order {
		if j := m.jobs[id]; j != nil {
			j.mu.Lock()
			running := j.state == "running"
			j.mu.Unlock()
			if running {
				return nil, errors.New("已有靓号任务在跑，先停止它（多任务会互相抢 CPU）")
			}
		}
	}

	job := &VanityJob{
		ID:      newID(),
		Prefix:  prefix,
		Want:    want,
		Workers: m.workers,
		started: time.Now(),
		state:   "running",
		cancel:  make(chan struct{}),
	}
	m.jobs[job.ID] = job
	m.order = append([]string{job.ID}, m.order...)

	for i := 0; i < job.Workers; i++ {
		go m.work(job)
	}
	v := jobView(job)
	return &v, nil
}

func (m *VanityManager) work(job *VanityJob) {
	const batch = 128
	seeds := make([]byte, 32*batch)
	for {
		select {
		case <-job.cancel:
			return
		default:
		}
		if _, err := rand.Read(seeds); err != nil {
			job.stop("error")
			return
		}
		for i := 0; i < batch; i++ {
			exp, addr, err := newOnionIdentity(seeds[i*32 : (i+1)*32])
			if err != nil {
				job.stop("error")
				return
			}
			atomic.AddUint64(&job.tested, 1)
			if strings.HasPrefix(addr, job.Prefix) {
				if !job.add(addr, exp) {
					return
				}
			}
		}
	}
}

func (m *VanityManager) List() []VanityView {
	m.mu.Lock()
	jobs := make([]*VanityJob, 0, len(m.order))
	for _, id := range m.order {
		if j := m.jobs[id]; j != nil {
			jobs = append(jobs, j)
		}
	}
	m.mu.Unlock()

	out := make([]VanityView, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobView(j))
	}
	return out
}

func (m *VanityManager) Get(id string) (*VanityJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}

func (m *VanityManager) Stop(id string) bool {
	j, ok := m.Get(id)
	if !ok {
		return false
	}
	j.stop("stopped")
	return true
}

func jobView(j *VanityJob) VanityView {
	j.mu.Lock()
	found := make([]VanityResult, len(j.found))
	copy(found, j.found)
	state := j.state
	ended := j.ended
	j.mu.Unlock()

	tested := atomic.LoadUint64(&j.tested)
	end := time.Now()
	if !ended.IsZero() {
		end = ended
	}
	elapsed := end.Sub(j.started).Seconds()
	speed := 0.0
	if elapsed > 0 {
		speed = float64(tested) / elapsed
	}

	keySpace := math.Pow(32, float64(len(j.Prefix)))
	eta := 0.0
	if state == "running" && speed > 0 {
		remaining := keySpace - float64(tested)
		if remaining < 0 {
			remaining = 0
		}
		eta = remaining / speed
	}

	v := VanityView{
		ID: j.ID, Prefix: j.Prefix, State: state, Want: j.Want, Workers: j.Workers,
		Found: found, Tested: tested, Speed: speed, ETA: eta,
		Started: j.started, Elapsed: elapsed, KeySpace: keySpace,
	}
	if !ended.IsZero() {
		t := ended
		v.Ended = &t
	}
	return v
}

// KeySpaceLabel is a human hint for how hard a prefix is.
func KeySpaceLabel(prefix string) string {
	if prefix == "" {
		return ""
	}
	ks := math.Pow(32, float64(len(prefix)))
	return fmt.Sprintf("%.0f 种组合", ks)
}
