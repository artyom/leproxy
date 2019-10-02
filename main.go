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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/artyom/autoflags"
	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/kardianos/service"
	"github.com/mholt/certmagic"
	yaml "gopkg.in/yaml.v2"
)

// ProxyHandler holds the info and handler of each proxy
type ProxyHandler struct {
	HostName   string
	TargetName string
	Handler    http.Handler
}

type program struct{}

type bufPool struct{}

func (bp bufPool) Get() []byte  { return bufferPool.Get().([]byte) }
func (bp bufPool) Put(b []byte) { bufferPool.Put(b) }

type runArgs struct {
	Addr          string `flag:"addr,Address to listen at"`
	HTTP          string `flag:"http,Optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	MappingPath   string `flag:"mapping,File with host/backend mapping"`
	CacheDir      string `flag:"cache-dir,Path to directory to cache key and certificates"`
	HTTPOnly      bool   `flag:"http-only,Only use http"`
	TLSSkipVerify bool   `flag:"tls-skip-verify,Skip verification of SSL certs for proxy targets"`
	HSTS          bool   `flag:"hsts,Add Strict-Transport-Security header"`
	HostName      string `flag:"hostname,The default host name to be used with any and / prefix options"`
	Email         string `flag:"email,Contact email address presented to letsencrypt CA"`
	Install       bool   `flag:"install,Installs as a windows service"`
	Remove        bool   `flag:"remove,Removes the windows service"`
}

var (
	args = runArgs{
		Addr:     ":https",
		HTTP:     ":http",
		CacheDir: cachePath(),
	}
	proxy      = Proxy{}
	bufferPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
	proxyCounter int
)

func main() {

	// Get teh working directory
	wd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Unable to get working directory: %s", err.Error())
		return
	}

	args.MappingPath = filepath.Join(wd, "mapping.yml")

	autoflags.Parse(&args)

	// Add the arguments to Windows services
	serviceArgs := []string{
		"-addr",
		fmt.Sprintf("\"%s\"", args.Addr),
		"-http",
		fmt.Sprintf("\"%s\"", args.HTTP),
		"-conf",
		fmt.Sprintf("\"%s\"", args.MappingPath),
		"-cache-dir",
		fmt.Sprintf("\"%s\"", args.CacheDir),
	}
	if args.HTTPOnly {
		serviceArgs = append(serviceArgs, "-http-only")
	}
	if args.TLSSkipVerify {
		serviceArgs = append(serviceArgs, "-tls-skip-verify")
	}
	if args.HSTS {
		serviceArgs = append(serviceArgs, "-hsts")
	}
	if args.HostName != "" {
		serviceArgs = append(serviceArgs, "-hostname")
		serviceArgs = append(serviceArgs, args.HostName)
	}
	if args.Email != "" {
		serviceArgs = append(serviceArgs, "-email")
		serviceArgs = append(serviceArgs, args.Email)
	}

	svcConfig := &service.Config{
		Name:        "sweetssl",
		DisplayName: "Sweet SSL",
		Description: "Provides a reverse proxy with Let's Encrypt SSL support",
		Arguments:   serviceArgs,
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

	if !args.HTTPOnly && args.Email == "" {
		log.Fatal("An email must be provided for Let's Encrypt validation")
	}

	err := godotenv.Load()
	if !os.IsNotExist(err) && err != nil {
		log.Fatal("Error loading .env file")
	}

	err = godotenv.Load("env")
	if !os.IsNotExist(err) && err != nil {
		log.Fatal("Error loading .env file")
	}

	mapping, err := readMapping(args.MappingPath)
	if err != nil {
		return err
	}

	err = loadProxies(mapping)
	if err != nil {
		return err
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
				mapping, err := readMapping(args.MappingPath)
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
	if err := watcher.Add(args.MappingPath); err != nil {
		return err
	}

	if args.HTTPOnly {
		// Serve http only
		log.Printf("Running on http only %s", args.Addr)
		srv := &http.Server{
			Handler: &proxy,
			Addr:    args.Addr,
		}
		return srv.ListenAndServe()
	}

	// Read and agree to your CA's legal documents
	certmagic.Default.Agreed = true

	// Provide an email address
	certmagic.Default.Email = args.Email

	// Set the cache path
	certmagic.Default.Storage = &certmagic.FileStorage{Path: args.CacheDir}

	return certmagic.HTTPS(hostnames(mapping), &proxy)

}

func loadProxies(mapping map[string]string) error {
	if len(mapping) == 0 {
		return fmt.Errorf("empty mapping")
	}
	// Add the each mapping
	proxyCounter = 0
	for hostname, backendAddr := range mapping {
		hostname, backendAddr := hostname, backendAddr // intentional shadowing
		if proxy.Exists(hostname, backendAddr) {
			// The handler already exists and hasn't changed
			proxyCounter++
			continue
		}
		if strings.ContainsRune(hostname, os.PathSeparator) {
			log.Printf("Invalid hostname: %s", hostname)
			continue
		}
		network := "tcp"
		if backendAddr != "" && backendAddr[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is
			// calculated in a way compatible with some other
			// implementations (i.e. uwsgi)
			network, backendAddr = "unix", backendAddr+string(0)
		} else if filepath.IsAbs(backendAddr) {
			network = "unix"
			if strings.HasSuffix(strings.Trim(backendAddr, ""), string(os.PathSeparator)) {
				// path specified as directory with explicit trailing
				// slash; add this path as static site
				proxy.Handle(hostname, &ProxyHandler{
					HostName:   hostname,
					TargetName: backendAddr,
					Handler:    http.FileServer(http.Dir(backendAddr)),
				})
				proxyCounter++
				continue
			}
		} else if u, err := url.Parse(backendAddr); err == nil {
			switch u.Scheme {
			case "http", "https":
				prefix := ""
				if strings.HasPrefix(hostname, "/") {
					prefix = hostname
				}
				rp := newSingleHostReverseProxy(u, prefix)
				rp.ErrorLog = log.New(ioutil.Discard, "", 0)
				rp.BufferPool = bufPool{}
				proxy.Handle(hostname, &ProxyHandler{
					HostName:   hostname,
					TargetName: backendAddr,
					Handler:    rp,
				})
				proxyCounter++
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
		proxyCounter++
	}
	log.Printf("%v mappings have been loaded", proxyCounter)
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

func hostnames(m map[string]string) []string {
	out := []string{}
	if args.HostName != "" {
		out = append(out, args.HostName)
	}
	for k := range m {
		if k != "any" || strings.HasPrefix(k, "/") {
			// Get the hostnames ignoring the any and prefixes
			out = append(out, k)
		}
	}
	return out
}

// newSingleHostReverseProxy is a copy of httputil.NewSingleHostReverseProxy
// with addition of "X-Forwarded-Proto" header.
func newSingleHostReverseProxy(target *url.URL, prefix string) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path[len(prefix):])
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
	if args.TLSSkipVerify {
		return &httputil.ReverseProxy{
			Director: director,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return &httputil.ReverseProxy{
		Director: director,
	}
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
