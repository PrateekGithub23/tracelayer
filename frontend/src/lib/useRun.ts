// Poll a background run (pipeline / evaluation / benchmark) until it finishes,
// then invalidate the queries whose data it changed.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "./api";

export function useRun(invalidate: string[][] = []) {
  const qc = useQueryClient();
  const [runId, setRunId] = useState<string | null>(null);
  const run = useQuery({
    queryKey: ["run", runId],
    queryFn: () => api.run(runId!),
    enabled: !!runId,
    refetchInterval: (q) => (q.state.data && ["succeeded", "failed"].includes(q.state.data.status) ? false : 800),
  });
  const done = run.data && ["succeeded", "failed"].includes(run.data.status);
  useEffect(() => {
    if (done) invalidate.forEach((key) => qc.invalidateQueries({ queryKey: key }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);
  return { run: run.data, start: setRunId, active: !!runId && !done };
}
