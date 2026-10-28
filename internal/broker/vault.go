package broker

import (
	"sync"

	"github.com/fount-labs/fount-broker/internal/policy"
)

// Vault holds credentials. The app can set them but has no request that reads
// one back. It lives in memory for now; persisting it to the Keychain is the
// next step.
type Vault struct {
	mu       sync.RWMutex
	secrets  map[policy.Credential]string
	onChange map[policy.Credential]func()
}

func NewVault() *Vault {
	return &Vault{secrets: map[policy.Credential]string{}, onChange: map[policy.Credential]func(){}}
}

// OnChange registers f to run after name is set.
func (v *Vault) OnChange(name policy.Credential, f func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onChange[name] = f
}

// Set stores a credential; an empty value removes it.
func (v *Vault) Set(name policy.Credential, value string) {
	v.mu.Lock()
	if value == "" {
		delete(v.secrets, name)
	} else {
		v.secrets[name] = value
	}
	f := v.onChange[name]
	v.mu.Unlock()
	if f != nil {
		f()
	}
}

func (v *Vault) Get(name policy.Credential) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.secrets[name]
	return s, ok
}
