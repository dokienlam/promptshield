package main

import "strings"

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Category string

const (
	CategoryInjection Category = "prompt_injection"
	CategoryPII       Category = "pii"
	CategoryJailbreak Category = "jailbreak"
	CategorySecret    Category = "secret"
)

type Finding struct {
	Category Category `json:"category"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Match    string   `json:"match,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type Detector interface {
	Name() string
	Scan(text string) []Finding
}

type Pipeline struct {
	detectors []Detector
}

func DefaultPipeline() *Pipeline {
	return &Pipeline{
		detectors: []Detector{
			NewInjectionDetector(),
			NewJailbreakDetector(),
			NewPIIDetector(),
			NewSecretDetector(),
		},
	}
}

func (p *Pipeline) Run(text string) []Finding {
	if text == "" {
		return nil
	}
	var all []Finding
	for _, d := range p.detectors {
		all = append(all, d.Scan(text)...)
	}
	return all
}

func hasSeverity(findings []Finding, min Severity) bool {
	rank := map[Severity]int{SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3}
	for _, f := range findings {
		if rank[f.Severity] >= rank[min] {
			return true
		}
	}
	return false
}

func applyRedactions(text string, findings []Finding) string {
	out := text
	for _, f := range findings {
		if f.Match == "" {
			continue
		}
		placeholder := "[REDACTED:" + string(f.Category) + ":" + f.Rule + "]"
		out = strings.ReplaceAll(out, f.Match, placeholder)
	}
	return out
}
