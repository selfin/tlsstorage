package tlsstorage

import (
	"crypto/tls"
	"github.com/gorilla/mux"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/selfin/tlsstorage/tlsbackends"
	"net"
	"net/http"
)

func ExampleNewTLSStorage() {
	fileB, err := tlsbackends.NewFileBackend("/tmp/")
	if err != nil {
		panic(err)
	}
	// import ( consulapi "github.com/hashicorp/consul/api" )
	consulB, err := tlsbackends.NewConsulBackend(consulapi.DefaultConfig(), "ssl")
	if err != nil {
		panic(err)
	}
	cStor, err := NewTLSStorage(fileB, consulB)
	if err != nil {
		panic(err)
	}
	cStor.SetDefault("www.example.com")
	cStor.Dynamic("^.\\.example\\.com")
	if err := cStor.Require("www.example.com", "api.example.com"); err != nil {
		panic(err)
	}

	conf := &tls.Config{}
	conf.GetCertificate = cStor.GetCertificate()
	rls, err := net.Listen("tcp", ":8000")
	if err != nil {
		panic(err)
	}
	ls := tls.NewListener(rls, conf)
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); return })

	http.Serve(ls, r)
}
