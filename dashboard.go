package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
)

//go:embed dashboard.html
var dashboardFS embed.FS

type Dashboard struct {
	store *Store
	tmpl  *template.Template
}

func NewDashboard(s *Store) *Dashboard {
	tmpl := template.Must(template.ParseFS(dashboardFS, "dashboard.html"))
	return &Dashboard{store: s, tmpl: tmpl}
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		d.serveIndex(w, r)
	case "/api/stats":
		d.serveStats(w, r)
	case "/api/recent":
		d.serveRecent(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (d *Dashboard) serveStats(w http.ResponseWriter, r *http.Request) {
	st, err := d.store.Stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, st)
}

func (d *Dashboard) serveRecent(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	entries, err := d.store.Recent(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, entries)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
