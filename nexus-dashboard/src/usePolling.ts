import { useEffect, useRef, useState } from "react";

interface PollState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function usePolling<T>(fetchFn: () => Promise<T>, intervalMs: number): PollState<T> {
  const [state, setState] = useState<PollState<T>>({ data: null, loading: true, error: null });
  const fetchFnRef = useRef(fetchFn);
  fetchFnRef.current = fetchFn;

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const data = await fetchFnRef.current();
        if (!cancelled) {
          setState({ data, loading: false, error: null });
        }
      } catch (err) {
        if (!cancelled) {
          setState((prev) => ({ data: prev.data, loading: false, error: (err as Error).message }));
        }
      }
    }

    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [intervalMs]);

  return state;
}
