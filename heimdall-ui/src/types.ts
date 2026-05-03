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

export interface FlowFilters {
  query: string;
  connection: string | null;
  hideErrors: boolean;
}
