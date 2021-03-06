package pwhash

import (
	"fmt"
	"sync"
)

var (
	adapters   = make(map[string]Adapter)
	adaptersMU sync.Mutex
)

// RawHashConfig represents unparsed config data from config file
type RawHashConfig = map[string]interface{}

// Adapter defines methods for pwhash adapters
type Adapter interface {
	//GetHasher returns desired PwHasher depends on the given config
	GetPwHasher(*RawHashConfig) (PwHasher, error)
}

// RegisterAdapter register pwhash adapter
func RegisterAdapter(name string, a Adapter) {
	adaptersMU.Lock()
	defer adaptersMU.Unlock()

	if name == "" {
		panic("adapter Name can't be empty")
	}

	if _, ok := adapters[name]; ok {
		panic("multiply RegisterAdapter call for adapter " + name)
	}

	adapters[name] = a
}

// GetAdapter returns pwhash adapter if it exists
func GetAdapter(name string) (Adapter, error) {
	adaptersMU.Lock()
	defer adaptersMU.Unlock()

	if a, ok := adapters[name]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("can't find adapter named %s", name)
}
