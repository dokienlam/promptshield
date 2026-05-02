package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type Mode int

const (
	ModeBlock Mode = iota
	ModeRedact
	ModeObserve
)

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "redact":
		return ModeRedact
	case "observe":
		return ModeObserve
	default:
		return ModeBlock
	}
}

func (m Mode) String() string {
	switch m {
	case ModeRedact:
		return "redact"
	case ModeObserve:
		return "observe"
	default:
		return "block"
	}
}

type Proxy struct {
	pipeline *Pipeline
	store    *Store
	mode     Mode
	clients  map[string]*targetClient
}

type targetClient struct {
	target *url.URL
	rp     *httputil.ReverseProxy
}

func NewProxy(p *Pipeline, s *Store, m Mode) *Proxy {
	clients := map[string]*targetClient{}
	for prefix, raw := range map[string]string{
		"/openai/":    "https://api.openai.com",
		"/anthropic/": "https://api.anthropic.com",
		"/gemini/":    "https://generativelanguage.googleapis.com",
	} {
		u, _ := url.Parse(raw)
		clients[prefix] = newSingleHostClient(u, prefix)
	}
	return &Proxy{pipeline: p, store: s, mode: m, clients: clients}
}

func newSingleHostClient(u *url.URL, prefix string) *targetClient {
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	hostHeader := u.Host
	stripPrefix := prefix
	rp.Director = func(req *http.Request) {
		orig(req)
		req.Host = hostHeader
		req.URL.Path = strings.TrimPrefix(req.URL.Path, strings.TrimSuffix(stripPrefix, "/"))
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
	}
	return &targetClient{target: u, rp: rp}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	provider, client := p.pickClient(r.URL.Path)
	if client == nil {
		http.Error(w, "unknown route — use /openai/, /anthropic/, or /gemini/ prefix", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.Body.Close()

	prompt := extractPromptText(provider, body)
	findings := p.pipeline.Run(prompt)

	logEntry := &LogEntry{
		Timestamp: start,
		Provider:  provider,
		Path:      r.URL.Path,
		Method:    r.Method,
		Findings:  findings,
		BodyBytes: len(body),
		Mode:      p.mode.String(),
	}

	if hasSeverity(findings, SeverityHigh) && p.mode == ModeBlock {
		logEntry.Action = "blocked"
		logEntry.Status = http.StatusForbidden
		logEntry.LatencyMs = time.Since(start).Milliseconds()
		_ = p.store.Insert(logEntry)
		writeBlockResponse(w, findings)
		return
	}

	outBody := body
	if p.mode == ModeRedact || (p.mode == ModeBlock && hasSeverity(findings, SeverityMedium)) {
		redacted := redactPromptText(provider, body, findings)
		if redacted != nil {
			outBody = redacted
			logEntry.Action = "redacted"
		}
	}
	if logEntry.Action == "" {
		if len(findings) > 0 {
			logEntry.Action = "flagged"
		} else {
			logEntry.Action = "passed"
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(outBody))
	r.ContentLength = int64(len(outBody))
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(outBody)))

	rec := &statusRecorder{ResponseWriter: w, status: 200}
	client.rp.ServeHTTP(rec, r)

	logEntry.Status = rec.status
	logEntry.LatencyMs = time.Since(start).Milliseconds()
	if err := p.store.Insert(logEntry); err != nil {
		log.Printf("store insert: %v", err)
	}
}

func (p *Proxy) pickClient(path string) (string, *targetClient) {
	for prefix, c := range p.clients {
		if strings.HasPrefix(path, prefix) {
			provider := strings.Trim(prefix, "/")
			return provider, c
		}
	}
	return "", nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func writeBlockResponse(w http.ResponseWriter, findings []Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := map[string]any{
		"error":    "request blocked by promptshield",
		"findings": findings,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func extractPromptText(provider string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return string(body)
	}
	var sb strings.Builder
	switch provider {
	case "openai":
		if msgs, ok := raw["messages"].([]any); ok {
			for _, m := range msgs {
				if mm, ok := m.(map[string]any); ok {
					appendContent(&sb, mm["content"])
				}
			}
		}
		if p, ok := raw["prompt"].(string); ok {
			sb.WriteString(p)
		}
	case "anthropic":
		if sys, ok := raw["system"].(string); ok {
			sb.WriteString(sys)
			sb.WriteString("\n")
		}
		if msgs, ok := raw["messages"].([]any); ok {
			for _, m := range msgs {
				if mm, ok := m.(map[string]any); ok {
					appendContent(&sb, mm["content"])
				}
			}
		}
	case "gemini":
		if contents, ok := raw["contents"].([]any); ok {
			for _, c := range contents {
				if cm, ok := c.(map[string]any); ok {
					if parts, ok := cm["parts"].([]any); ok {
						for _, p := range parts {
							if pm, ok := p.(map[string]any); ok {
								if t, ok := pm["text"].(string); ok {
									sb.WriteString(t)
									sb.WriteString("\n")
								}
							}
						}
					}
				}
			}
		}
	}
	if sb.Len() == 0 {
		return string(body)
	}
	return sb.String()
}

func appendContent(sb *strings.Builder, c any) {
	switch v := c.(type) {
	case string:
		sb.WriteString(v)
		sb.WriteString("\n")
	case []any:
		for _, item := range v {
			if im, ok := item.(map[string]any); ok {
				if t, ok := im["text"].(string); ok {
					sb.WriteString(t)
					sb.WriteString("\n")
				}
			}
		}
	}
}

func redactPromptText(provider string, body []byte, findings []Finding) []byte {
	if len(findings) == 0 || len(body) == 0 {
		return nil
	}
	piiFindings := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Category == CategoryPII {
			piiFindings = append(piiFindings, f)
		}
	}
	if len(piiFindings) == 0 {
		return nil
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	switch provider {
	case "openai", "anthropic":
		if msgs, ok := raw["messages"].([]any); ok {
			for i, m := range msgs {
				if mm, ok := m.(map[string]any); ok {
					mm["content"] = redactContent(mm["content"], piiFindings)
					msgs[i] = mm
				}
			}
			raw["messages"] = msgs
		}
		if sys, ok := raw["system"].(string); ok {
			raw["system"] = applyRedactions(sys, piiFindings)
		}
	case "gemini":
		if contents, ok := raw["contents"].([]any); ok {
			for i, c := range contents {
				if cm, ok := c.(map[string]any); ok {
					if parts, ok := cm["parts"].([]any); ok {
						for j, pt := range parts {
							if pm, ok := pt.(map[string]any); ok {
								if t, ok := pm["text"].(string); ok {
									pm["text"] = applyRedactions(t, piiFindings)
									parts[j] = pm
								}
							}
						}
						cm["parts"] = parts
					}
					contents[i] = cm
				}
			}
			raw["contents"] = contents
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	return out
}

func redactContent(c any, findings []Finding) any {
	switch v := c.(type) {
	case string:
		return applyRedactions(v, findings)
	case []any:
		for i, item := range v {
			if im, ok := item.(map[string]any); ok {
				if t, ok := im["text"].(string); ok {
					im["text"] = applyRedactions(t, findings)
					v[i] = im
				}
			}
		}
		return v
	}
	return c
}
