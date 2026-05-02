package main

import (
	"regexp"
	"strings"
)

type injectionRule struct {
	name     string
	pattern  *regexp.Regexp
	severity Severity
}

type InjectionDetector struct {
	rules []injectionRule
}

func NewInjectionDetector() *InjectionDetector {
	rules := []injectionRule{
		{"ignore_previous", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|messages?|context|rules?|directives?)\b`), SeverityHigh},
		{"override_system", regexp.MustCompile(`(?i)\b(reveal|show|print|output|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+(prompt|instructions?)|hidden\s+(prompt|instructions?))\b`), SeverityHigh},
		{"persona_override", regexp.MustCompile(`(?i)\byou\s+are\s+(now|no\s+longer|not)\s+(a|an)?\s*\w+`), SeverityMedium},
		{"role_switch", regexp.MustCompile(`(?i)\b(act|behave|pretend|roleplay)\s+as\s+(a|an|if)\b`), SeverityMedium},
		{"developer_mode", regexp.MustCompile(`(?i)\b(developer|admin|debug|maintenance|god)\s+mode\b`), SeverityHigh},
		{"end_of_prompt", regexp.MustCompile(`(?i)(\[END\s+OF\s+PROMPT\]|<\|im_end\|>|<\|end\|>|###\s*END\s*###)`), SeverityHigh},
		{"new_instructions", regexp.MustCompile(`(?i)\b(new|updated|revised)\s+(instructions?|rules?|prompt|directives?)\s*(:|follow|are)\b`), SeverityMedium},
		{"output_directive", regexp.MustCompile(`(?i)\b(only\s+respond|only\s+output|always\s+respond|reply\s+only)\s+(with|using|in)\b`), SeverityLow},
		{"data_exfil", regexp.MustCompile(`(?i)\b(send|forward|post|leak|exfiltrate|email)\s+(this|the|all|your)\s+(data|information|prompt|context|history|conversation)\s+(to|at)\b`), SeverityHigh},
		{"prompt_leak_attempt", regexp.MustCompile(`(?i)\b(what\s+(were|are)\s+your\s+(initial\s+)?instructions|repeat\s+the\s+text\s+above|print\s+everything\s+above)\b`), SeverityHigh},
		{"instruction_marker", regexp.MustCompile(`(?i)(<\s*system\s*>|<\s*\/?\s*instructions?\s*>|\[\s*system\s*\])`), SeverityMedium},
	}
	return &InjectionDetector{rules: rules}
}

func (d *InjectionDetector) Name() string { return "injection" }

func (d *InjectionDetector) Scan(text string) []Finding {
	var out []Finding
	for _, r := range d.rules {
		if loc := r.pattern.FindStringIndex(text); loc != nil {
			out = append(out, Finding{
				Category: CategoryInjection,
				Rule:     r.name,
				Severity: r.severity,
				Match:    text[loc[0]:loc[1]],
			})
		}
	}
	return out
}

type JailbreakDetector struct {
	rules []injectionRule
}

func NewJailbreakDetector() *JailbreakDetector {
	rules := []injectionRule{
		{"dan", regexp.MustCompile(`(?i)\bDAN\b.*\b(do\s+anything\s+now|jailbreak|unrestricted)\b`), SeverityHigh},
		{"dan_alt", regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`), SeverityHigh},
		{"unfiltered", regexp.MustCompile(`(?i)\b(unfiltered|uncensored|unrestricted|no\s+(filters?|guidelines?|restrictions?|rules?))\b`), SeverityMedium},
		{"hypothetical_evil", regexp.MustCompile(`(?i)\b(hypothetically|imagine|suppose)\b.*\b(no\s+(rules?|laws?|ethics)|illegal|harmful)\b`), SeverityMedium},
		{"refusal_bypass", regexp.MustCompile(`(?i)\b(don'?t\s+refuse|never\s+refuse|cannot\s+(say|refuse)\s+no|always\s+answer)\b`), SeverityMedium},
		{"grandma_exploit", regexp.MustCompile(`(?i)\b(my\s+(grandma|grandmother|deceased)).*\b(used\s+to|would)\b`), SeverityLow},
	}
	return &JailbreakDetector{rules: rules}
}

func (d *JailbreakDetector) Name() string { return "jailbreak" }

func (d *JailbreakDetector) Scan(text string) []Finding {
	var out []Finding
	lower := strings.ToLower(text)
	_ = lower
	for _, r := range d.rules {
		if loc := r.pattern.FindStringIndex(text); loc != nil {
			out = append(out, Finding{
				Category: CategoryJailbreak,
				Rule:     r.name,
				Severity: r.severity,
				Match:    text[loc[0]:loc[1]],
			})
		}
	}
	return out
}
