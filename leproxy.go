// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bytes"
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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/artyom/autoflags"
	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/service"
	"golang.org/x/crypto/acme/autocert"
	yaml "gopkg.in/yaml.v2"
)

var args = runArgs{
	Addr:  ":https",
	HTTP:  ":http",
	Conf:  "mapping.yml",
	Cache: cachePath(),
	RTo:   time.Minute,
	WTo:   5 * time.Minute,
}

var (
	proxy = Proxy{}
	certs autocert.Manager
)

func main() {

	autoflags.Parse(&args)

	svcConfig := &service.Config{
		Name:        "leproxy",
		DisplayName: "Let's Encrypt Proxy",
		Description: "Provides a reverse proxy with Let's Encrypt SSL support",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if args.Install {
		err = s.Install()
		if err != nil {
			log.Fatalf("Unable to install application: %s", err.Error())
		} else {
			log.Fatalf("Service installed: %s", svcConfig.DisplayName)
		}
	} else if args.Remove {
		err = s.Uninstall()
		if err != nil {
			log.Fatalf("Unable to remove application: %s", err.Error())
		} else {
			log.Fatalf("Service removed: %s", svcConfig.DisplayName)
		}
	} else {
		err = s.Run()
		if err != nil {
			log.Fatalf("Unable to run application: %s", err.Error())
		}
	}

}

// Proxy contains and servers the handlers for each hostname
type Proxy struct {
	hostMap sync.Map
}

// Handle adds a handler if it doesn't exist
func (proxy *Proxy) Handle(host string, handler *ProxyHandler) {
	proxy.hostMap.Store(host, handler)
}

// Exists returns whether there is an
func (proxy *Proxy) Exists(host, target string) bool {
	item, ok := proxy.hostMap.Load(host)
	if !ok {
		return false
	}
	return item.(*ProxyHandler).TargetName == target
}

func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	result, ok := proxy.hostMap.Load(r.Host)
	if ok {
		handler := result.(*ProxyHandler)
		handler.Handler.ServeHTTP(w, r)
	} else {
		http.Error(w, "Not found", 404)
	}
}

// ProxyHandler holds the info and handler of each proxy
type ProxyHandler struct {
	HostName   string
	TargetName string
	Handler    http.Handler
}

type runArgs struct {
	Addr    string `flag:"addr,address to listen at"`
	Conf    string `flag:"map,file with host/backend mapping"`
	Cache   string `flag:"cacheDir,path to directory to cache key and certificates"`
	HSTS    bool   `flag:"hsts,add Strict-Transport-Security header"`
	Email   string `flag:"email,contact email address presented to letsencrypt CA"`
	HTTP    string `flag:"http,optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	Install bool   `flag:"install,installs as a windows service"`
	Remove  bool   `flag:"remove,removes the windows service"`

	RTo  time.Duration `flag:"rto,maximum duration before timing out read of the request"`
	WTo  time.Duration `flag:"wto,maximum duration before timing out write of the response"`
	Idle time.Duration `flag:"idle,how long idle connection is kept before closing (set rto, wto to 0 to use this)"`
}

type program struct{}

func (p *program) Start(s service.Service) error {
	// Set the working directory to be the current one
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	os.Chdir(dir)
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	return nil
}

func (p *program) run() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	if args.Cache == "" {
		return fmt.Errorf("no cache specified")
	}
	srv, httpHandler, err := setupServer(args.Addr, args.Cache, args.Email, args.HSTS)
	if err != nil {
		return err
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.RTo > 0 {
		srv.ReadTimeout = args.RTo
	}
	if args.WTo > 0 {
		srv.WriteTimeout = args.WTo
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				fmt.Println(event.Name, event.Op)
				mapping, err := readMapping(args.Conf)
				if err != nil {
					fmt.Println("ERROR", event.Name, event.Op, err)
				} else {
					loadProxies(mapping)
				}
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	// Watch the mapping file....
	if err := watcher.Add(args.Conf); err != nil {
		return err
	}

	if args.HTTP != "" {
		go func(addr string) {
			srv := http.Server{
				Addr:         addr,
				Handler:      httpHandler,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			log.Fatal(srv.ListenAndServe()) // TODO: should return err from run, not exit like this
		}(args.HTTP)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || args.Idle == 0 {
		return srv.ListenAndServeTLS("", "")
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	ln = tcpKeepAliveListener{d: args.Idle,
		TCPListener: ln.(*net.TCPListener)}
	return srv.ServeTLS(ln, "", "")
}

func setupServer(addr, cacheDir, email string, hsts bool) (*http.Server, http.Handler, error) {
	mapping, err := readMapping(args.Conf)
	if err != nil {
		return nil, nil, err
	}
	certs = autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(keys(mapping)...),
		Email:      email,
	}
	err = loadProxies(mapping)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("cannot create cache directory %q: %v", cacheDir, err)
	}
	srv := &http.Server{
		Handler:   &proxy,
		Addr:      addr,
		TLSConfig: certs.TLSConfig(),
	}
	return srv, certs.HTTPHandler(nil), nil
}

func loadProxies(mapping map[string]string) error {
	if len(mapping) == 0 {
		return fmt.Errorf("empty mapping")
	}
	// Update the host policy with any new hosts
	certs.HostPolicy = autocert.HostWhitelist(keys(mapping)...)
	// Add the each mapping
	for hostname, backendAddr := range mapping {
		hostname, backendAddr := hostname, backendAddr // intentional shadowing
		if proxy.Exists(hostname, backendAddr) {
			// The handler already exists and hasn't changed
			continue
		}
		if strings.ContainsRune(hostname, os.PathSeparator) {
			return fmt.Errorf("invalid hostname: %q", hostname)
		}
		network := "tcp"
		if backendAddr != "" && backendAddr[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is
			// calculated in a way compatible with some other
			// implementations (i.e. uwsgi)
			network, backendAddr = "unix", backendAddr+string(0)
		} else if filepath.IsAbs(backendAddr) {
			network = "unix"
			if strings.HasSuffix(backendAddr, string(os.PathSeparator)) {
				// path specified as directory with explicit trailing
				// slash; add this path as static site
				proxy.Handle(hostname, &ProxyHandler{
					HostName:   hostname,
					TargetName: backendAddr,
					Handler:    http.FileServer(http.Dir(backendAddr)),
				})
				continue
			}
		} else if u, err := url.Parse(backendAddr); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := newSingleHostReverseProxy(u)
				rp.ErrorLog = log.New(ioutil.Discard, "", 0)
				rp.BufferPool = bufPool{}
				proxy.Handle(hostname, &ProxyHandler{
					HostName:   hostname,
					TargetName: backendAddr,
					Handler:    rp,
				})
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
		proxy.Handle(hostname, &ProxyHandler{
			HostName:   hostname,
			TargetName: backendAddr,
			Handler:    rp,
		})
	}
	return nil
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

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	d time.Duration
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	if ln.d == 0 {
		return tc, nil
	}
	return timeoutConn{d: ln.d, TCPConn: tc}, nil
}

// timeoutConn extends deadline after successful read or write operations
type timeoutConn struct {
	d time.Duration
	*net.TCPConn
}

func (c timeoutConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}
