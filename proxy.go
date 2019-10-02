package main

import (
	"net/http"
	"strings"
	"sync"
)

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

// ServeHTTP finds the handler if one exists and then returns the result
func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	// Match to hostname
	result, ok := proxy.hostMap.Load(r.Host)
	if ok {
		// Found a handler so serve
		handler := result.(*ProxyHandler)
		handler.Handler.ServeHTTP(w, r)
		return
	}
	// Match against the path prefix
	url := strings.Split(r.RequestURI, "/")
	if len(url) > 1 {
		result, ok = proxy.hostMap.Load("/" + url[1])
		if ok {
			// Found a handler so serve
			handler := result.(*ProxyHandler)
			handler.Handler.ServeHTTP(w, r)
			return
		}
	}
	// Hostname doesn't match so try wildcard
	result, ok = proxy.hostMap.Load("any")
	if ok {
		// Found a wildcard handler
		handler := result.(*ProxyHandler)
		handler.Handler.ServeHTTP(w, r)
	} else {
		http.Error(w, "Not found", 404)
	}

}
