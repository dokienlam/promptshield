package main

import "regexp"

type piiRule struct {
	name     string
	pattern  *regexp.Regexp
	severity Severity
	validate func(string) bool
}

type PIIDetector struct {
	rules []piiRule
}

func NewPIIDetector() *PIIDetector {
	rules := []piiRule{
		{
			name:     "email",
			pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			severity: SeverityMedium,
		},
		{
			name:     "us_phone",
			pattern:  regexp.MustCompile(`\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b`),
			severity: SeverityMedium,
		},
		{
			name:     "ssn",
			pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "credit_card",
			pattern:  regexp.MustCompile(`\b(?:\d[ \-]*?){13,19}\b`),
			severity: SeverityHigh,
			validate: looksLikeCreditCard,
		},
		{
			name:     "ipv4",
			pattern:  regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`),
			severity: SeverityLow,
		},
		{
			name:     "iban",
			pattern:  regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
			severity: SeverityHigh,
		},
	}
	return &PIIDetector{rules: rules}
}

func (d *PIIDetector) Name() string { return "pii" }

func (d *PIIDetector) Scan(text string) []Finding {
	var out []Finding
	for _, r := range d.rules {
		matches := r.pattern.FindAllString(text, -1)
		for _, m := range matches {
			if r.validate != nil && !r.validate(m) {
				continue
			}
			out = append(out, Finding{
				Category: CategoryPII,
				Rule:     r.name,
				Severity: r.severity,
				Match:    m,
			})
		}
	}
	return out
}

func looksLikeCreditCard(s string) bool {
	digits := make([]int, 0, len(s))
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		} else if c != ' ' && c != '-' {
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
}

type SecretDetector struct {
	rules []piiRule
}

func NewSecretDetector() *SecretDetector {
	rules := []piiRule{
		{
			name:     "openai_key",
			pattern:  regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "anthropic_key",
			pattern:  regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "aws_access_key",
			pattern:  regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "github_token",
			pattern:  regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "google_api_key",
			pattern:  regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "slack_token",
			pattern:  regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}\b`),
			severity: SeverityHigh,
		},
		{
			name:     "private_key_block",
			pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			severity: SeverityHigh,
		},
	}
	return &SecretDetector{rules: rules}
}

func (d *SecretDetector) Name() string { return "secret" }

func (d *SecretDetector) Scan(text string) []Finding {
	var out []Finding
	for _, r := range d.rules {
		matches := r.pattern.FindAllString(text, -1)
		for _, m := range matches {
			out = append(out, Finding{
				Category: CategorySecret,
				Rule:     r.name,
				Severity: r.severity,
				Match:    m,
			})
		}
	}
	return out
}
