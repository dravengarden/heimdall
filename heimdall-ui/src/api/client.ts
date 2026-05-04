import type { Flow, Message, Status } from "../types";

const base = "";

export async function fetchFlows(params: {
  limit?: number;
  connection?: string;
  pod?: string;
  host?: string;
} = {}): Promise<Flow[]> {
  const qs = new URLSearchParams();
  qs.set("limit", String(params.limit ?? 200));
  if (params.connection) qs.set("connection", params.connection);
  if (params.pod) qs.set("pod", params.pod);
  if (params.host) qs.set("host", params.host);

  const res = await fetch(`${base}/api/flows?${qs}`);
  if (!res.ok) throw new Error(`flows HTTP ${res.status}`);
  return res.json();
}

export async function fetchFlow(id: number): Promise<Flow> {
  const res = await fetch(`${base}/api/flows/${id}`);
  if (!res.ok) throw new Error(`flow ${id} HTTP ${res.status}`);
  return res.json();
}

export async function fetchStatus(): Promise<Status> {
  const res = await fetch(`${base}/api/status`);
  if (!res.ok) throw new Error(`status HTTP ${res.status}`);
  return res.json();
}

export async function fetchFlowMessages(
  flowId: number,
  params: { limit?: number; sinceUs?: number } = {},
): Promise<Message[]> {
  const qs = new URLSearchParams();
  qs.set("limit", String(params.limit ?? 500));
  if (params.sinceUs != null) qs.set("since_us", String(params.sinceUs));
  const res = await fetch(`${base}/api/flows/${flowId}/messages?${qs}`);
  if (!res.ok) throw new Error(`messages flow=${flowId} HTTP ${res.status}`);
  return res.json();
}
