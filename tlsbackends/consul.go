package tlsbackends

import (
	"crypto/tls"
	"fmt"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/selfin/tlsstorage"
	"sync"
	"time"
)

type consulTLSBackend struct {
	mu         sync.RWMutex
	client     *consulapi.Client
	prefix     string
	updates    chan<- tlsstorage.TLSCert
	sources    []string
	fqdns      []string
	loadedMeta map[string]*consulapi.KVPair
}

func NewConsulBackend(conf *consulapi.Config, prefix string) (tlsstorage.Backend, error) {
	var err error
	var newClient *consulapi.Client
	newClient, err = consulapi.NewClient(conf)
	if err != nil {
		return nil, err
	}
	ctb := &consulTLSBackend{
		client:     newClient,
		prefix:     prefix,
		fqdns:      make([]string, 0),
		loadedMeta: make(map[string]*consulapi.KVPair),
	}

	go func() {
		updateTicker := time.NewTicker(time.Minute)
		defer updateTicker.Stop()
		for {
			select {
			case <-updateTicker.C:
				for _, name := range ctb.fqdns {
					ctb.scanFor(name)
				}
			}
		}
	}()
	return ctb, nil
}

func (ctb *consulTLSBackend) Updates(new chan<- tlsstorage.TLSCert) {
	ctb.mu.Lock()
	ctb.updates = new
	ctb.mu.Unlock()
}

// checkFile tries to find if update for file path needed
// return true if file not presented in loadedMeta map or ModTime changed
func (ctb *consulTLSBackend) checkMeta(path string, info *consulapi.KVPair) bool {
	ctb.mu.Lock()
	defer ctb.mu.Unlock()
	var ok bool
	var curInfo *consulapi.KVPair
	if curInfo, ok = ctb.loadedMeta[path]; !ok {
		ctb.loadedMeta[path] = info
		return true
	}
	if curInfo.ModifyIndex != info.ModifyIndex {
		ctb.loadedMeta[path] = info
		return true
	}
	// update not needed
	return false
}

func (ctb *consulTLSBackend) scanFor(fqdn string) error {
	crt_path := fmt.Sprintf("%v/%v.crt", ctb.prefix, fqdn)
	key_path := fmt.Sprintf("%v/%v.key", ctb.prefix, fqdn)

	var err error
	var crtKP, keyKP *consulapi.KVPair
	if crtKP, _, err = ctb.client.KV().Get(crt_path, nil); err != nil || crtKP == nil {
		return tlsstorage.NotFoundError{FQDN: fqdn}
	}
	if keyKP, _, err = ctb.client.KV().Get(key_path, nil); err != nil || keyKP == nil {
		return tlsstorage.NotFoundError{FQDN: fqdn}
	}
	if ctb.checkMeta(crt_path, crtKP) || ctb.checkMeta(key_path, keyKP) {
		var crt tls.Certificate

		if crt, err = tls.X509KeyPair(crtKP.Value, keyKP.Value); err != nil {
			return err
		}
		ctb.mu.RLock()
		defer ctb.mu.RUnlock()
		if ctb.updates != nil {
			new_tls_cert := &tlsCertificate{
				N:   fqdn,
				Crt: &crt,
			}
			ctb.updates <- new_tls_cert
			return nil

		}
	}
	return tlsstorage.NotFoundError{FQDN: fqdn}
}

func (ctb *consulTLSBackend) Subscribe(new_fqdn string) (err error) {
	for _, fqdn := range ctb.fqdns {
		if fqdn == new_fqdn {
			return nil
		}
	}
	if err = ctb.scanFor(new_fqdn); err == nil {
		ctb.fqdns = append(ctb.fqdns, new_fqdn)
		return nil
	}
	return
}
