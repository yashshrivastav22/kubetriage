package controller

import "regexp"

const redactedEvidenceValue = "[REDACTED]"

type evidenceRedactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var evidenceRedactionRules = []evidenceRedactionRule{
	{
		pattern: regexp.MustCompile(
			`(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`,
		),
		replacement: redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`(?i)\bauthorization\s*:\s*bearer\s+[^\s,;]+`,
		),
		replacement: "Authorization: Bearer " + redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`(?i)\bauthorization\s*:\s*basic\s+[^\s,;]+`,
		),
		replacement: "Authorization: Basic " + redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`,
		),
		replacement: "Bearer " + redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@`,
		),
		replacement: `${1}` + redactedEvidenceValue + `@`,
	},
	{
		pattern: regexp.MustCompile(
			`(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|client[_-]?secret|secret|access[_-]?key|secret[_-]?key)\b\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
		),
		replacement: `${1}=` + redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
		),
		replacement: redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`\bghp_[A-Za-z0-9]{20,}\b`,
		),
		replacement: redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`\bgithub_pat_[A-Za-z0-9_]{20,}\b`,
		),
		replacement: redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`\bglpat-[A-Za-z0-9_-]{20,}\b`,
		),
		replacement: redactedEvidenceValue,
	},
	{
		pattern: regexp.MustCompile(
			`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`,
		),
		replacement: redactedEvidenceValue,
	},
}

func sanitizeEvidenceText(value string) string {
	sanitized := value

	for i := range evidenceRedactionRules {
		rule := &evidenceRedactionRules[i]

		sanitized = rule.pattern.ReplaceAllString(
			sanitized,
			rule.replacement,
		)
	}

	return sanitized
}

func sanitizeAndTruncateEvidence(
	value string,
	maxRunes int,
) string {
	return truncateRunes(
		sanitizeEvidenceText(value),
		maxRunes,
	)
}
