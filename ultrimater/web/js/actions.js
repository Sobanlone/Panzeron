import { api, ApiError } from './api.js';
import { confirmDialog, toast } from './ui.js';

// Runs a response action. Anything needing confirmation shows the exact description first.
export async function runAction(a, finding, after) {
  let confirm = false;
  if (a.requires_confirmation) {
    confirm = await confirmDialog({ title: a.label, body: a.description + (a.reversible ? ' This can be reversed.' : ''), confirmLabel: a.label, danger: a.destructive });
    if (!confirm) return;
  }
  try {
    const r = await api.post(`/api/findings/${finding.id}/action`, { type: a.type, confirm });
    const d = r.detail || {};
    toast(d.message || (d.copy ? `Saved copy: ${d.copy}` : `${a.label}: done`));
    after && after();
  } catch (e) {
    toast(e instanceof ApiError ? e.message : String(e), true);
  }
}
