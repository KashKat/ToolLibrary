package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Port        int               `json:"port"`
	UseHTTPS    bool              `json:"use_https"`
	CertFile    string            `json:"cert_file"`
	KeyFile     string            `json:"key_file"`
	DefaultFile string            `json:"default_file"`
	BaseDir     string            `json:"base_dir"`
	Redirects   map[string]string `json:"redirects"`
}

func loadConfig(configPath string) (*Config, error) {
	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func serveFileOrDirectory(w http.ResponseWriter, r *http.Request, path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	if info.IsDir() {
		http.StripPrefix(r.URL.Path, http.FileServer(http.Dir(path))).ServeHTTP(w, r)
	} else {
		http.ServeFile(w, r, path)
	}
	return true
}

func handler(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log basic request info
		is64ps := r.URL.Query().Get("is64ps")
		username := r.URL.Query().Get("username")

		remoteIP := strings.Split(r.RemoteAddr, ":")[0]
		log.Printf("[+] %s %s from %s", r.Method, r.URL.Path, remoteIP)
		if is64ps != "" {
			log.Printf("[i] Param 'is64ps': %s", is64ps)
		}
		if username != "" {
			log.Printf("[i] Param 'username': %s", username)
		}

		// Redirect check
		for prefix, dir := range config.Redirects {
			if strings.HasPrefix(r.URL.Path, prefix) {
				relPath := strings.TrimPrefix(r.URL.Path, prefix)
				target := filepath.Join(dir, relPath)
				log.Printf("[*] Redirect match: %s → %s", r.URL.Path, target)
				if serveFileOrDirectory(w, r, target) {
					log.Printf("[✓] 200 OK: %s", target)
				} else {
					log.Printf("[x] 404 Not Found: %s", target)
				}
				return
			}
		}

		// Default: Serve from base_dir
		requestedPath := strings.TrimPrefix(r.URL.Path, "/")
		target := filepath.Join(config.BaseDir, requestedPath)

		if serveFileOrDirectory(w, r, target) {
			log.Printf("[✓] 200 OK (base_dir): %s", target)
		} else {
			log.Printf("[x] 404 Not Found (base_dir): %s", target)
			http.NotFound(w, r)
		}
	}
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("[!] Failed to load config: %v", err)
	}

	http.HandleFunc("/", handler(config))

	addr := fmt.Sprintf(":%d", config.Port)

	if config.UseHTTPS {
		log.Printf("[*] Starting HTTPS server on %s", addr)
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			log.Fatalf("[!] Failed to load cert/key: %v", err)
		}
		server := &http.Server{
			Addr:      addr,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Printf("[*] Starting HTTP server on %s", addr)
		log.Fatal(http.ListenAndServe(addr, nil))
	}
}
