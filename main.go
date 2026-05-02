package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "0.1.0"

func main() {
	var (
		listen   = flag.String("listen", ":8080", "address to listen on")
		dbPath   = flag.String("db", "promptshield.db", "path to SQLite log database")
		dashAddr = flag.String("dashboard", ":8081", "dashboard listen address (empty to disable)")
		mode     = flag.String("mode", "block", "mode: block, redact, or observe")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("promptshield", version)
		return
	}

	store, err := OpenStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	pipeline := DefaultPipeline()
	proxy := NewProxy(pipeline, store, ParseMode(*mode))

	mux := http.NewServeMux()
	mux.Handle("/", proxy)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	var dashSrv *http.Server
	if *dashAddr != "" {
		dashSrv = &http.Server{
			Addr:              *dashAddr,
			Handler:           NewDashboard(store),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	go func() {
		log.Printf("promptshield %s — proxy listening on %s (mode=%s)", version, *listen, *mode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy server: %v", err)
		}
	}()

	if dashSrv != nil {
		go func() {
			log.Printf("dashboard listening on http://localhost%s", *dashAddr)
			if err := dashSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("dashboard server: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if dashSrv != nil {
		_ = dashSrv.Shutdown(ctx)
	}
}
