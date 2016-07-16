// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rsc.io/letsencrypt"

	"gopkg.in/yaml.v2"

	"github.com/artyom/autoflags"
)

func main() {
	params := struct {
		Addr  string `flag:"addr,address to listen at"`
		Conf  string `flag:"map,file with host/backend mapping"`
		Cache string `flag:"cache,path to letsencypt cache file"`
		HSTS  bool   `flag:"hsts,add Strict-Transport-Security header"`
	}{
		Addr:  ":https",
		Conf:  "mapping.yml",
		Cache: "letsencrypt.cache",
	}
	autoflags.Define(&params)
	flag.Parse()
	if params.Cache == "" {
		log.Fatal("no cache specified")
	}
	srv, err := setupServer(params.Addr, params.Conf, params.Cache, params.HSTS)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func setupServer(addr, mapfile, cachefile string, hsts bool) (*http.Server, error) {
	mapping, err := readMapping(mapfile)
	if err != nil {
		return nil, err
	}
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, err
	}
	if hsts {
		proxy = &hstsProxy{proxy}
	}
	var m letsencrypt.Manager
	if err := m.CacheFile(cachefile); err != nil {
		return nil, err
	}
	m.SetHosts(keys(mapping))
	srv := &http.Server{
		Handler:   proxy,
		Addr:      addr,
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	return srv, nil
}

func setProxy(mapping map[string]string) (http.Handler, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	mux := http.NewServeMux()
	for hostname, backendAddr := range mapping {
		hostname, backendAddr := hostname, backendAddr // intentional shadowing
		if strings.ContainsRune(hostname, os.PathSeparator) {
			return nil, fmt.Errorf("invalid hostname: %q", hostname)
		}
		network := "tcp"
		if filepath.IsAbs(backendAddr) {
			network = "unix"
			if strings.HasSuffix(backendAddr, string(os.PathSeparator)) {
				// path specified as directory with explicit trailing
				// slash; add this path as static site
				mux.Handle(hostname+"/", http.FileServer(http.Dir(backendAddr)))
				continue
			}
		}
		if u, err := url.Parse(backendAddr); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := httputil.NewSingleHostReverseProxy(u)
				rp.ErrorLog = log.New(ioutil.Discard, "", 0)
				rp.BufferPool = bufPool{}
				mux.Handle(hostname+"/", rp)
				continue
			}
		}
		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
			},
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					return net.DialTimeout(network, backendAddr, 5*time.Second)
				},
			},
			ErrorLog:   log.New(ioutil.Discard, "", 0),
			BufferPool: bufPool{},
		}
		mux.Handle(hostname+"/", rp)
	}
	return mux, nil
}

func readMapping(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lr := io.LimitReader(f, 1<<20)
	b := new(bytes.Buffer)
	if _, err := io.Copy(b, lr); err != nil {
		return nil, err
	}
	m := make(map[string]string)
	if err := yaml.Unmarshal(b.Bytes(), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type hstsProxy struct {
	http.Handler
}

func (p *hstsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	p.Handler.ServeHTTP(w, r)
}

type bufPool struct{}

func (bp bufPool) Get() []byte  { return bufferPool.Get().([]byte) }
func (bp bufPool) Put(b []byte) { bufferPool.Put(b) }

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}
