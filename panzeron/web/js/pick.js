import { api } from './api.js';
import { toast } from './ui.js';

// Opens the real Windows file/folder dialog (through the engine). Returns [] if cancelled.
// If the dialog cannot open, tells the user and calls `fallback` (which reveals manual path entry).
export async function pickPaths(kind, title, filter = 'all', fallback = null) {
  try {
    const r = await api.post('/api/pick', { kind, title, filter });
    if (r.unavailable) { toast(r.message, true); if (fallback) fallback(); return []; }
    return r.paths || [];
  } catch (e) { toast(e.message, true); if (fallback) fallback(); return []; }
}
