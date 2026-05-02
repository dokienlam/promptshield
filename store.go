package main

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type LogEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Provider  string    `json:"provider"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	Status    int       `json:"status"`
	BodyBytes int       `json:"body_bytes"`
	LatencyMs int64     `json:"latency_ms"`
	Mode      string    `json:"mode"`
	Action    string    `json:"action"`
	Findings  []Finding `json:"findings"`
}

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			provider TEXT,
			path TEXT,
			method TEXT,
			status INTEGER,
			body_bytes INTEGER,
			latency_ms INTEGER,
			mode TEXT,
			action TEXT,
			findings TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_requests_action ON requests(action);
	`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Insert(e *LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	findingsJSON, _ := json.Marshal(e.Findings)
	res, err := s.db.Exec(
		`INSERT INTO requests (timestamp, provider, path, method, status, body_bytes, latency_ms, mode, action, findings)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Provider, e.Path, e.Method, e.Status, e.BodyBytes, e.LatencyMs, e.Mode, e.Action, string(findingsJSON),
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	e.ID = id
	return nil
}

func (s *Store) Recent(limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, provider, path, method, status, body_bytes, latency_ms, mode, action, findings
		 FROM requests ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		var findingsJSON string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Provider, &e.Path, &e.Method, &e.Status, &e.BodyBytes, &e.LatencyMs, &e.Mode, &e.Action, &findingsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(findingsJSON), &e.Findings)
		out = append(out, e)
	}
	return out, rows.Err()
}

type Stats struct {
	Total      int            `json:"total"`
	Blocked    int            `json:"blocked"`
	Redacted   int            `json:"redacted"`
	Flagged    int            `json:"flagged"`
	Passed     int            `json:"passed"`
	ByProvider map[string]int `json:"by_provider"`
	TopRules   []RuleCount    `json:"top_rules"`
	Last24h    int            `json:"last_24h"`
	AvgLatency float64        `json:"avg_latency_ms"`
}

type RuleCount struct {
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Count    int    `json:"count"`
}

func (s *Store) Stats() (*Stats, error) {
	st := &Stats{ByProvider: map[string]int{}}
	row := s.db.QueryRow(`SELECT COUNT(*), COALESCE(AVG(latency_ms), 0) FROM requests`)
	if err := row.Scan(&st.Total, &st.AvgLatency); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`SELECT action, COUNT(*) FROM requests GROUP BY action`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a string
		var c int
		_ = rows.Scan(&a, &c)
		switch a {
		case "blocked":
			st.Blocked = c
		case "redacted":
			st.Redacted = c
		case "flagged":
			st.Flagged = c
		case "passed":
			st.Passed = c
		}
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT provider, COUNT(*) FROM requests GROUP BY provider`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		var c int
		_ = rows.Scan(&p, &c)
		st.ByProvider[p] = c
	}
	rows.Close()

	row = s.db.QueryRow(`SELECT COUNT(*) FROM requests WHERE timestamp > datetime('now','-1 day')`)
	_ = row.Scan(&st.Last24h)

	rows, err = s.db.Query(`SELECT findings FROM requests WHERE findings IS NOT NULL AND findings != '' AND findings != 'null'`)
	if err != nil {
		return nil, err
	}
	counts := map[string]*RuleCount{}
	for rows.Next() {
		var raw string
		_ = rows.Scan(&raw)
		var fs []Finding
		if err := json.Unmarshal([]byte(raw), &fs); err != nil {
			continue
		}
		for _, f := range fs {
			key := string(f.Category) + "/" + f.Rule
			if c, ok := counts[key]; ok {
				c.Count++
			} else {
				counts[key] = &RuleCount{Category: string(f.Category), Rule: f.Rule, Count: 1}
			}
		}
	}
	rows.Close()
	for _, c := range counts {
		st.TopRules = append(st.TopRules, *c)
	}
	for i := 0; i < len(st.TopRules); i++ {
		for j := i + 1; j < len(st.TopRules); j++ {
			if st.TopRules[j].Count > st.TopRules[i].Count {
				st.TopRules[i], st.TopRules[j] = st.TopRules[j], st.TopRules[i]
			}
		}
	}
	if len(st.TopRules) > 10 {
		st.TopRules = st.TopRules[:10]
	}
	return st, nil
}
