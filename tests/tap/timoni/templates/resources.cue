// CUE's @embed reads files relative to the .cue file at evaluation
// time. The package-level `@extern(embed)` attribute opts the file
// in to embedding (CUE 0.11+).
@extern(embed)

package templates

// The .js / .ts under ../scripts/ are the source of truth for the
// test workloads — embedded here as strings so the ConfigMap stays
// in sync without any manual generation step.
// `type=text` reads the file as a plain UTF-8 string. Without it CUE
// tries to infer a parser from the extension and rejects .js/.ts.
bunScript:  string @embed(file="scripts/boringssl-bun.js", type=text)
denoScript: string @embed(file="scripts/rustls-deno.ts",  type=text)

#Namespace: {
	#config: #Config

	apiVersion: "v1"
	kind:       "Namespace"
	metadata: {
		name:   #config.metadata.namespace
		labels: #config.metadata.labels
	}
}

#ConfigMap: {
	#config: #Config

	apiVersion: "v1"
	kind:       "ConfigMap"
	metadata: {
		name:      "\(#config.metadata.name)-scripts"
		namespace: #config.metadata.namespace
		labels:    #config.metadata.labels
	}
	data: {
		"boringssl-bun.js": bunScript
		"rustls-deno.ts":   denoScript
	}
}

#Pod: {
	#config: #Config

	apiVersion: "v1"
	kind:       "Pod"
	metadata: {
		name:      #config.metadata.name
		namespace: #config.metadata.namespace
		labels:    #config.metadata.labels
	}
	spec: {
		restartPolicy: "Always"
		containers: [
			{
				name:  "bun"
				image: #config.images.bun
				// `bun run` interprets the .js file directly; no build step.
				command: ["bun", "run", "/scripts/boringssl-bun.js"]
				volumeMounts: [{
					name:      "scripts"
					mountPath: "/scripts"
					readOnly:  true
				}]
			},
			{
				name:  "deno"
				image: #config.images.deno
				// --allow-net is required because Deno is opt-in by default.
				command: ["deno", "run", "--allow-net", "/scripts/rustls-deno.ts"]
				volumeMounts: [{
					name:      "scripts"
					mountPath: "/scripts"
					readOnly:  true
				}]
			},
		]
		volumes: [{
			name: "scripts"
			configMap: name: "\(#config.metadata.name)-scripts"
		}]
	}
}
