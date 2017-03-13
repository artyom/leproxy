// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bytes"
	"crypto/tls"
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

	"github.com/artyom/autoflags"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v2"
)

func main() {
	params := struct {
		Addr  string `flag:"addr,address to listen at"`
		Conf  string `flag:"map,file with host/backend mapping"`
		Cache string `flag:"cacheDir,path to directory to cache key and certificates"`
		HSTS  bool   `flag:"hsts,add Strict-Transport-Security header"`
		Email string `flag:"email,contact email address presented to letsencrypt CA"`

		RTo time.Duration `flag:"rto,maximum duration before timing out read of the request"`
		WTo time.Duration `flag:"wto,maximum duration before timing out write of the response"`
	}{
		Addr:  ":https",
		Conf:  "mapping.yml",
		Cache: "/var/cache/letsencrypt",
		RTo:   time.Minute,
		WTo:   5 * time.Minute,
	}
	autoflags.Parse(&params)
	if params.Cache == "" {
		log.Fatal("no cache specified")
	}
	srv, err := setupServer(params.Addr, params.Conf, params.Cache, params.Email, params.HSTS)
	if err != nil {
		log.Fatal(err)
	}
	if params.RTo > 0 {
		srv.ReadTimeout = params.RTo
	}
	if params.WTo > 0 {
		srv.WriteTimeout = params.WTo
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func setupServer(addr, mapfile, cacheDir, email string, hsts bool) (*http.Server, error) {
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
	if fi, err := os.Stat(cacheDir); err == nil && !fi.IsDir() {
		return nil, fmt.Errorf("path %q already exists and is not a directory", cacheDir)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(keys(mapping)...),
		Email:      email,
	}
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
				rp := newSingleHostReverseProxy(u)
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
				req.Header.Set("X-Forwarded-Proto", "https")
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

// newSingleHostReverseProxy is a copy of httputil.NewSingleHostReverseProxy
// with addition of "X-Forwarded-Proto" header.
func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return &httputil.ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
