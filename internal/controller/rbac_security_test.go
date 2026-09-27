package controller

import (
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// verbsForResource returns the union of verbs granted to a resource
// in a specific API group.
func verbsForResource(
	role *rbacv1.ClusterRole,
	apiGroup string,
	resource string,
) []string {
	verbs := make(map[string]struct{})

	for _, rule := range role.Rules {
		groupMatches := false

		for _, group := range rule.APIGroups {
			if group == apiGroup {
				groupMatches = true
				break
			}
		}

		if !groupMatches {
			continue
		}

		resourceMatches := false

		for _, ruleResource := range rule.Resources {
			if ruleResource == resource {
				resourceMatches = true
				break
			}
		}

		if !resourceMatches {
			continue
		}

		for _, verb := range rule.Verbs {
			verbs[verb] = struct{}{}
		}
	}

	result := make(
		[]string,
		0,
		len(verbs),
	)

	for verb := range verbs {
		result = append(
			result,
			verb,
		)
	}

	return result
}

func resourceGranted(
	role *rbacv1.ClusterRole,
	apiGroup string,
	resource string,
) bool {
	return len(
		verbsForResource(
			role,
			apiGroup,
			resource,
		),
	) > 0
}

var _ = Describe("Generated RBAC security", func() {
	var role *rbacv1.ClusterRole

	BeforeEach(func() {
		rolePath := filepath.Join(
			"..",
			"..",
			"config",
			"rbac",
			"role.yaml",
		)

		rawYAML, err := os.ReadFile(rolePath)
		Expect(err).NotTo(HaveOccurred())

		rawJSON, err := utilyaml.ToJSON(rawYAML)
		Expect(err).NotTo(HaveOccurred())

		role = &rbacv1.ClusterRole{}

		Expect(
			json.Unmarshal(
				rawJSON,
				role,
			),
		).To(Succeed())
	})

	It("grants only read access to application Pods", func() {
		Expect(
			verbsForResource(
				role,
				"",
				"pods",
			),
		).To(ConsistOf(
			"get",
			"list",
			"watch",
		))
	})

	It("grants only get access to Pod logs", func() {
		Expect(
			verbsForResource(
				role,
				"",
				"pods/log",
			),
		).To(ConsistOf(
			"get",
		))
	})

	It("grants only read access to Kubernetes Events", func() {
		Expect(
			verbsForResource(
				role,
				"events.k8s.io",
				"events",
			),
		).To(ConsistOf(
			"get",
			"list",
			"watch",
		))
	})

	It("grants only read access to IncidentPolicy objects", func() {
		Expect(
			verbsForResource(
				role,
				"ops.kubetriage.dev",
				"incidentpolicies",
			),
		).To(ConsistOf(
			"get",
			"list",
			"watch",
		))
	})

	It("allows IncidentPolicy status updates without spec modification", func() {
		Expect(
			verbsForResource(
				role,
				"ops.kubetriage.dev",
				"incidentpolicies/status",
			),
		).To(ConsistOf(
			"get",
			"patch",
			"update",
		))
	})

	It("allows IncidentReport creation and read access but no deletion or spec mutation", func() {
		Expect(
			verbsForResource(
				role,
				"ops.kubetriage.dev",
				"incidentreports",
			),
		).To(ConsistOf(
			"create",
			"get",
			"list",
			"watch",
		))
	})

	It("allows IncidentReport lifecycle updates only through status", func() {
		Expect(
			verbsForResource(
				role,
				"ops.kubetriage.dev",
				"incidentreports/status",
			),
		).To(ConsistOf(
			"get",
			"patch",
			"update",
		))
	})

	It("does not grant access to Kubernetes Secrets", func() {
		Expect(
			resourceGranted(
				role,
				"",
				"secrets",
			),
		).To(BeFalse())
	})

	It("does not grant access to ConfigMaps", func() {
		Expect(
			resourceGranted(
				role,
				"",
				"configmaps",
			),
		).To(BeFalse())
	})

	It("does not grant Pod exec access", func() {
		Expect(
			resourceGranted(
				role,
				"",
				"pods/exec",
			),
		).To(BeFalse())
	})

	It("does not grant access to workload controllers", func() {
		for _, resource := range []string{
			"deployments",
			"statefulsets",
			"daemonsets",
			"replicasets",
		} {
			Expect(
				resourceGranted(
					role,
					"apps",
					resource,
				),
			).To(BeFalse())
		}
	})

	It("does not grant Node access", func() {
		Expect(
			resourceGranted(
				role,
				"",
				"nodes",
			),
		).To(BeFalse())
	})

	It("contains no wildcard API groups, resources, or verbs", func() {
		for _, rule := range role.Rules {
			Expect(rule.APIGroups).NotTo(
				ContainElement("*"),
			)

			Expect(rule.Resources).NotTo(
				ContainElement("*"),
			)

			Expect(rule.Verbs).NotTo(
				ContainElement("*"),
			)
		}
	})

	It("contains no delete permissions", func() {
		for _, rule := range role.Rules {
			Expect(rule.Verbs).NotTo(
				ContainElement("delete"),
			)

			Expect(rule.Verbs).NotTo(
				ContainElement("deletecollection"),
			)
		}
	})
})
