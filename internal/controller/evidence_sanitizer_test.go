package controller

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Evidence sanitizer", func() {
	It("redacts password values", func() {
		input :=
			"database connection failed password=SuperSecret123"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			ContainSubstring(
				"password=[REDACTED]",
			),
		)

		Expect(output).NotTo(
			ContainSubstring(
				"SuperSecret123",
			),
		)
	})

	It("redacts API keys", func() {
		input :=
			"api_key=sk-example-secret-value"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			Equal(
				"api_key=[REDACTED]",
			),
		)
	})

	It("redacts bearer authorization headers", func() {
		input :=
			"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			Equal(
				"Authorization: Bearer [REDACTED]",
			),
		)
	})

	It("redacts credentials embedded in URLs", func() {
		input :=
			"postgres://admin:SuperSecret@database:5432/app"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			Equal(
				"postgres://[REDACTED]@database:5432/app",
			),
		)

		Expect(output).NotTo(
			ContainSubstring(
				"SuperSecret",
			),
		)
	})

	It("redacts AWS access key IDs", func() {
		input :=
			"aws key AKIA1234567890ABCDEF was rejected"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			Equal(
				"aws key [REDACTED] was rejected",
			),
		)
	})

	It("redacts private keys", func() {
		input := `startup failed
-----BEGIN PRIVATE KEY-----
super-secret-private-key-data
-----END PRIVATE KEY-----
application stopped`

		output :=
			sanitizeEvidenceText(input)

		Expect(output).NotTo(
			ContainSubstring(
				"super-secret-private-key-data",
			),
		)

		Expect(output).To(
			ContainSubstring(
				redactedEvidenceValue,
			),
		)
	})

	It("leaves normal diagnostic evidence unchanged", func() {
		input :=
			"container terminated with exit code 137 because memory limit was exceeded"

		output :=
			sanitizeEvidenceText(input)

		Expect(output).To(
			Equal(input),
		)
	})

	It("sanitizes before applying the rune limit", func() {
		input :=
			"password=SuperSecret " +
				strings.Repeat(
					"🙂",
					2000,
				)

		output :=
			sanitizeAndTruncateEvidence(
				input,
				1024,
			)

		Expect(
			[]rune(output),
		).To(HaveLen(1024))

		Expect(output).NotTo(
			ContainSubstring(
				"SuperSecret",
			),
		)

		Expect(output).To(
			ContainSubstring(
				"password=[REDACTED]",
			),
		)
	})
})
