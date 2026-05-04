import type { Flow, FlowFilters } from "../types";

export function flowMatches(f: Flow, filters: FlowFilters, nowUs: number): boolean {
  // Error mode
  if (filters.errorMode === "ok" && f.error) return false;
  if (filters.errorMode === "errors-only" && !f.error) return false;

  // Connections
  if (filters.connections.length > 0 && !filters.connections.includes(f.connection_name)) {
    return false;
  }

  // Port range
  if (filters.portMin != null && f.dst_port < filters.portMin) return false;
  if (filters.portMax != null && f.dst_port > filters.portMax) return false;

  // Bytes threshold
  if (filters.bytesMin != null && f.bytes_up + f.bytes_down < filters.bytesMin) {
    return false;
  }

  // Age (last N seconds)
  if (filters.ageMaxSec != null) {
    const ageSec = (nowUs - f.ts_start_us) / 1_000_000;
    if (ageSec > filters.ageMaxSec) return false;
  }

  // Free-text query (last because it's the most expensive)
  const q = filters.query.trim().toLowerCase();
  if (q.length > 0) {
    const fields: ReadonlyArray<string | null> = [
      f.dst_host,
      f.dst_ip,
      f.pod_name,
      f.namespace,
      f.connection_name,
      f.upstream_addr,
    ];
    return fields.some((s) => s != null && s.toLowerCase().includes(q));
  }
  return true;
}

export function isFiltered(filters: FlowFilters): boolean {
  return (
    filters.query.trim().length > 0 ||
    filters.connections.length > 0 ||
    filters.errorMode !== "all" ||
    filters.portMin != null ||
    filters.portMax != null ||
    filters.bytesMin != null ||
    filters.ageMaxSec != null
  );
}
