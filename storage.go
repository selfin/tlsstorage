// Package tlsstorage gives ability to dynamically load and update tls certificates
package tlsstorage

import (
	"crypto/tls"
	"fmt"
	"log"
	"regexp"
	"sync"
)

type TLSStorage struct {
	mu          sync.RWMutex
	defaultFQDN string
	autoAdd     bool
	whitelist   []*regexp.Regexp
	backends    []Backend
	storage     map[string]*tls.Certificate
	lookup      chan string
	certs       chan TLSCert
}

// NewTLSStorage creates TLS Storage which can be used
// as Certificate backend to handle dynamically changing domains
func NewTLSStorage(backends ...Backend) (*TLSStorage, error) {
	if len(backends) < 1 {
		return nil, fmt.Errorf("at least one backend required to create TLSStorage")
	}
	s := &TLSStorage{
		backends:  backends,
		whitelist: make([]*regexp.Regexp, 0),
		storage:   make(map[string]*tls.Certificate),
		lookup:    make(chan string, 1),
		certs:     make(chan TLSCert),
	}
	// certificate setter
	go func() {
		for crt := range s.certs {
			s.mu.Lock()
			s.storage[crt.Name()] = crt.Certificate()
			s.mu.Unlock()
		}
	}()
	// lookup requests handler
	go func() {
		states := make(map[string]bool)
		for fqdn := range s.lookup {
			if _, ok := states[fqdn]; !ok {
				if err := s.subscribe(fqdn); err != nil {
					log.Printf("Error occured for %v certificate discovery: %v", fqdn, err)
				} else {
					// source backend for certificate found
					// it'll send certificate
					states[fqdn] = true
				}
			}
		}
	}()

	for _, backend := range backends {
		backend.Updates(s.certs)
	}

	return s, nil
}

// subscribe notifies all backends about new Name
// all errors except NotFound will be raised
func (S *TLSStorage) subscribe(fqdn string) error {
	for _, backend := range S.backends {
		if err := backend.Subscribe(fqdn); err != nil {
			if _, ok := err.(NotFoundError); !ok {
				return err
			}
		}
	}
	return nil
}

func (S *TLSStorage) getter(fqdn string) (*tls.Certificate, error) {
	S.mu.RLock()
	defer S.mu.RUnlock()
	if fqdn == "" {
		if S.defaultFQDN == "" {
			return nil, fmt.Errorf("default Name not set, unable to accept non SNI requests")
		}
		fqdn = S.defaultFQDN

	}
	c, ok := S.storage[fqdn]
	if !ok {
		if S.autoAdd {
			var approved bool
			for _, pattern := range S.whitelist {
				if m := pattern.FindString(fqdn); m != "" {
					approved = true
				}
			}
			if approved {
				S.lookup <- fqdn
			} else {
				return nil, fmt.Errorf("%v not accepted for dynamic load", fqdn)
			}
		}
		return nil, fmt.Errorf("certificate for %v not loaded", fqdn)
	}
	return c, nil
}

// Dynamic enables dynamic certificate lookup
// each time client requests not available   certificate
// initiates certificate lookup with configured backend
// use whitelist to cover only needed domains
// whitelist syntax https://github.com/google/re2/wiki/Syntax
func (S *TLSStorage) Dynamic(whitelist ...string) error {
	compiledRegexp := make([]*regexp.Regexp, 0, len(whitelist))
	for _, pattern := range whitelist {
		if next, err := regexp.Compile(pattern); err == nil {
			compiledRegexp = append(compiledRegexp, next)
		} else {
			return err
		}
	}
	S.mu.Lock()
	S.autoAdd = true
	S.whitelist = append(S.whitelist, compiledRegexp...)
	S.mu.Unlock()
	return nil
}

// SetDefault set default Name
// Certificate loaded for this Name will be used for non SNI requests
func (S *TLSStorage) SetDefault(fqdn string) {
	S.mu.Lock()
	S.defaultFQDN = fqdn
	S.mu.Unlock()

}

// Require tries to get certificates synchronously with configured backends
// if any of  requested names won't be found error returns
func (S *TLSStorage) Require(fqdn ...string) error {
	for _, name := range fqdn {
		var found bool
		for _, backend := range S.backends {
			if err := backend.Subscribe(name); err == nil {
				found = true
			} else {
				if _, ok := err.(NotFoundError); !ok {
					log.Printf("Error occured for %v: %v", name, err)
				}
			}
		}
		if !found {
			return NotFoundError{FQDN: name}
		}
	}
	return nil
}

// GetCertificate is tls.Conf.GetCertificate replacement
func (S *TLSStorage) GetCertificate() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return S.getter(clientHello.ServerName)
	}
}

// TLSCert container for receive certificates from backends
type TLSCert interface {
	Name() string
	Certificate() *tls.Certificate
}

// Backend should find TLS certificates for requested with Subscribe domains and send
// to chanel set by Updates func, then they should resend certificates on any change
type Backend interface {
	// Updates gives backend chanel to sent discovered certificates to
	Updates(chan<- TLSCert)
	// Subscribe executes search of certificate with backend
	Subscribe(FQDN string) error
}

type NotFoundError struct {
	FQDN string
}

func (e NotFoundError) Error() string {
	return fmt.Sprintf("certificate for %v not found", e.FQDN)
}
