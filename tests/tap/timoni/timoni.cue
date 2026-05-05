// Timoni module entry point. `timoni apply` evaluates this file: the
// resources under `apply.app` are reconciled against the cluster.
package main

import (
	templates "heimdall.io/tests/tap/templates"
)

// `values` is what `--values` overrides at apply time. Defaults live
// in the schema so a no-flag apply works.
values: templates.#Config

timoni: {
	apiVersion: "v1alpha1"

	instance: templates.#Instance & {
		config: values
		// Metadata + version fields are injected by timoni from the CLI
		// flags (--name / --namespace / --version) and the cluster
		// kube-version probe. Each @tag corresponds to one piece of
		// runtime context.
		config: {
			metadata: {
				name:      string @tag(name)
				namespace: string @tag(namespace)
			}
			moduleVersion: string @tag(mv, var=moduleVersion)
			kubeVersion:   string @tag(kv, var=kubeVersion)
		}
	}

	apply: app: [for obj in instance.objects {obj}]
}
