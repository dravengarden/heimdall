package templates

// #Config is the schema for the values exposed by this module. Metadata
// (name, namespace, version) is populated by timoni at apply time via
// the @tag mechanism wired up in ../../timoni.cue, so we don't need to
// vendor `timoni.sh/core/v1alpha1` for a fixture this small.
#Config: {
	// Required by timoni; populated automatically from --kube-version.
	kubeVersion!: string
	// Required by timoni; populated from the module version OCI tag.
	moduleVersion!: string

	metadata: {
		name!:      string
		namespace!: string
		labels: {
			"app.kubernetes.io/name":     metadata.name
			"app.kubernetes.io/instance": metadata.name
			"app.kubernetes.io/version":  moduleVersion
			"app.kubernetes.io/part-of":  "heimdall-tap-tests"
			"app.kubernetes.io/managed-by": "timoni"
		}
	}

	// Container images. Both choices ship the TLS implementation we want
	// to exercise:
	//   bun  → statically-linked BoringSSL
	//   deno → rustls (via the deno_tls crate)
	images: {
		bun:  *"oven/bun:1"           | string
		deno: *"denoland/deno:alpine" | string
	}

	// Endpoint each container hits in a loop. Pick something cheap and
	// stable; httpbin.org is the standard for this kind of probe.
	targetURL:  *"https://httpbin.org/json" | string
	intervalMs: *5000                       | int & >=1000
}

// #Instance ties the resource templates together so timoni.cue can
// list them declaratively under `apply.app`.
#Instance: {
	config: #Config

	objects: {
		namespace: #Namespace & {#config: config}
		configMap: #ConfigMap & {#config: config}
		pod:       #Pod       & {#config: config}
	}
}
