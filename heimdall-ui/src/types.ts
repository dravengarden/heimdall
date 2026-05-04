// Wire types — must match heimdall::store::Flow
export interface Flow {
  id: number;
  socket_cookie: number | null;
  cgroup_id: number | null;
  pod_uid: string | null;
  namespace: string | null;
  pod_name: string | null;
  connection_name: string;
  dst_host: string | null;
  dst_ip: string;
  dst_port: number;
  ts_start_us: number;
  ts_end_us: number | null;
  bytes_up: number;
  bytes_down: number;
  upstream_addr: string | null;
  atyp: string | null;
  error: string | null;
}

export interface Status {
  version: string;
  config: string;
  connections: number;
  rules: number;
  default_connection: string;
  relay_listen: string;
  dns_listen: string;
  fake_ip_cidr: string;
  state_dir: string;
  flow_retention_secs: number;
  flows_count: number;
}

// Wire type — must match heimdall::api::ApiMessage. `body` is serialized
// by serde_json as a JSON array of byte values. The pod_* fields are
// resolved at API time from the daemon's cgroup → pod cache; null for
// host processes or pods the informer hasn't seen yet.
export interface Message {
  id: number;
  flow_id: number | null;
  ts_us: number;
  cgroup_id: number;
  tgid: number;
  /** 0 = send (SSL_write), 1 = recv (SSL_read return) */
  dir: 0 | 1;
  total_len: number;
  captured_len: number;
  body: readonly number[];
  pod_namespace: string | null;
  pod_name: string | null;
}

export type ErrorMode = "all" | "ok" | "errors-only";

export interface FlowFilters {
  /** free-text substring match across host / IP / pod / connection / upstream */
  query: string;
  /** empty array = all connections; otherwise rows must match one of these */
  connections: readonly string[];
  /** all = no filter; ok = drop rows with error; errors-only = keep only errors */
  errorMode: ErrorMode;
  /** inclusive lower bound on dst_port; null = no lower bound */
  portMin: number | null;
  /** inclusive upper bound on dst_port; null = no upper bound */
  portMax: number | null;
  /** minimum total bytes (up + down); null = no threshold */
  bytesMin: number | null;
  /** keep only flows whose ts_start is within the last N seconds; null = no limit */
  ageMaxSec: number | null;
}

export const DEFAULT_FILTERS: FlowFilters = {
  query: "",
  connections: [],
  errorMode: "all",
  portMin: null,
  portMax: null,
  bytesMin: null,
  ageMaxSec: null,
};
