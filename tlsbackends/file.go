package tlsbackends

import (
	"crypto/tls"
	"fmt"
	"github.com/selfin/tlsstorage"
	"os"
	"sync"
	"time"
)

type fileTLSBackend struct {
	mu          sync.RWMutex
	updates     chan<- tlsstorage.TLSCert
	sources     []string
	fqdns       []string
	loadedFiles map[string]os.FileInfo
}

func NewFileBackend(path ...string) (tlsstorage.Backend, error) {
	ftb := &fileTLSBackend{
		sources:     path,
		fqdns:       make([]string, 0),
		loadedFiles: make(map[string]os.FileInfo),
	}
	go func() {
		updateTicker := time.NewTicker(time.Minute)
		defer updateTicker.Stop()
		for {
			select {
			case <-updateTicker.C:
				for _, name := range ftb.fqdns {
					ftb.scanFor(name)
				}
			}
		}
	}()
	return ftb, nil
}

func (ftb *fileTLSBackend) Updates(new chan<- tlsstorage.TLSCert) {
	ftb.mu.Lock()
	ftb.updates = new
	ftb.mu.Unlock()
}

// checkFile tries to find if update for file path needed
// return true if file not presented in loadedFiles map or ModTime changed
func (ftb *fileTLSBackend) checkFile(path string, info os.FileInfo) bool {
	ftb.mu.Lock()
	defer ftb.mu.Unlock()
	var ok bool
	var curInfo os.FileInfo
	if curInfo, ok = ftb.loadedFiles[path]; !ok {
		ftb.loadedFiles[path] = info
		return true
	}
	if curInfo.ModTime() != info.ModTime() {
		return true
	}
	// update not needed
	return false
}

func (ftb *fileTLSBackend) scanFor(fqdn string) error {
	for _, path := range ftb.sources {
		if _, err := os.Stat(path); err == nil {
			crt_path := fmt.Sprintf("%v/%v.crt", path, fqdn)
			key_path := fmt.Sprintf("%v/%v.key", path, fqdn)
			var crtInfo, keyInfo os.FileInfo
			if crtInfo, err = os.Stat(crt_path); err != nil {
				continue
			}
			if keyInfo, err = os.Stat(key_path); err != nil {
				continue
			}
			if ftb.checkFile(crt_path, crtInfo) || ftb.checkFile(key_path, keyInfo) {
				var crt tls.Certificate
				if crt, err = tls.LoadX509KeyPair(crt_path, key_path); err != nil {
					return err
				}
				ftb.mu.RLock()
				defer ftb.mu.RUnlock()
				if ftb.updates != nil {
					new_tls_cert := &tlsCertificate{
						N:   fqdn,
						Crt: &crt,
					}
					ftb.updates <- new_tls_cert
					return nil

				}
			}
		}
	}
	return tlsstorage.NotFoundError{FQDN: fqdn}
}

func (ftb *fileTLSBackend) Subscribe(new_fqdn string) (err error) {
	for _, fqdn := range ftb.fqdns {
		if fqdn == new_fqdn {
			return nil
		}
	}
	if err = ftb.scanFor(new_fqdn); err == nil {
		ftb.fqdns = append(ftb.fqdns, new_fqdn)
		return nil
	}
	return
}
