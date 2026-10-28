// The loop waits for the whole read cycle before scheduling another one. Stopping
// invalidates callbacks as well as aborting fetch; it never cancels accepted work.
export function pollJob(options: {
  refresh: (signal: AbortSignal) => Promise<void>;
  pending: () => boolean;
  error: (error: unknown) => void;
  schedule?: (callback: () => void, milliseconds: number) => unknown;
  cancel?: (timer: unknown) => void;
}) {
  const controller = new AbortController();
  const schedule = options.schedule ?? ((callback, milliseconds) => setTimeout(callback, milliseconds));
  const cancel = options.cancel ?? (timer => clearTimeout(timer as ReturnType<typeof setTimeout>));
  let timer: unknown;
  let failures = 0;
  async function tick() {
    let delay = 2000;
    try {
      await options.refresh(controller.signal);
      failures = 0;
    } catch (error) {
      if (controller.signal.aborted) return;
      failures = Math.min(failures + 1, 5);
      delay = Math.min(2000 * 2 ** (failures - 1), 30_000);
      options.error(error);
    }
    if (!controller.signal.aborted && options.pending()) timer = schedule(() => { void tick(); }, delay);
  }
  void tick();
  return () => {
    controller.abort();
    if (timer !== undefined) cancel(timer);
  };
}

export type HistoryPage<T> = { events: T[]; next_cursor: string };
export function historyPage<T extends { event_id: string }>(value: unknown): HistoryPage<T> {
  if (!value || typeof value !== "object") throw new Error("History page is invalid.");
  const page = value as HistoryPage<T>;
  if (!Array.isArray(page.events) || typeof page.next_cursor !== "string" || page.next_cursor.length > 4096 || page.events.some(event => !event || typeof event.event_id !== "string") || new Set(page.events.map(event => event.event_id)).size !== page.events.length) throw new Error("History page is invalid.");
  return page;
}

export function appendHistory<T extends { event_id: string }>(previous: T[], page: HistoryPage<T>): T[] {
  const seen = new Set(previous.map(event => event.event_id));
  if (page.events.some(event => seen.has(event.event_id))) throw new Error("History continuation repeated an event. Refresh history to start a new snapshot.");
  return [...previous, ...page.events];
}
