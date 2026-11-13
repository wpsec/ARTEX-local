// Command agent-eval-lab serves synthetic Web/API controls for local Agent evaluation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type lab struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/__lab/stats" {
		l.mu.Lock()
		defer l.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(l.counts); err != nil {
			log.Printf("write lab statistics: %v", err)
		}
		return
	}
	l.mu.Lock()
	l.counts[r.URL.Path]++
	l.mu.Unlock()
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := fmt.Fprintln(w, "Local evaluation fixture. API: /api/a/records/{1,2}, /api/b/records/{1,2}; identify as alpha or beta using X-Lab-Actor. Record 1 belongs to alpha, record 2 to beta. Web: /web/a?q=, /web/b?q=."); err != nil {
			log.Printf("write lab instructions: %v", err)
		}
	case strings.HasPrefix(r.URL.Path, "/api/a/records/"):
		l.record(w, r, false)
	case strings.HasPrefix(r.URL.Path, "/api/b/records/"):
		l.record(w, r, true)
	case r.URL.Path == "/web/a" || r.URL.Path == "/web/b":
		value := r.URL.Query().Get("q")
		if r.URL.Path == "/web/b" {
			value = html.EscapeString(value)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := fmt.Fprintf(w, "<!doctype html><html><body><p>%s</p></body></html>", value); err != nil {
			log.Printf("write lab response: %v", err)
		}
	default:
		http.NotFound(w, r)
	}
}

func (l *lab) record(w http.ResponseWriter, r *http.Request, guarded bool) {
	actor := r.Header.Get("X-Lab-Actor")
	if actor != "alpha" && actor != "beta" {
		http.Error(w, "X-Lab-Actor must be alpha or beta", http.StatusUnauthorized)
		return
	}
	owner := ""
	switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
	case "1":
		owner = "alpha"
	case "2":
		owner = "beta"
	default:
		http.NotFound(w, r)
		return
	}
	if guarded && actor != owner {
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"owner": owner, "content": "synthetic record"}); err != nil {
		log.Printf("write lab record: %v", err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address; use an isolated container network for container access")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("evaluation fixture listening on %s", ln.Addr())
	server := &http.Server{Handler: &lab{counts: make(map[string]int)}, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.Serve(ln))
}
