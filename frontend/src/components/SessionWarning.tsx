// Warns before the session ends. Sessions slide on activity (idle timeout) and also have a hard cap.
// We do NOT poll the server to find out: a poll would itself count as activity and defeat the idle timeout.
// Instead the warning is computed from the last answered request and the limits the server reported.
import { TimerReset } from "lucide-react";
import { useEffect, useState } from "react";
import { api, isDemoTransport, lastActivityAt } from "../lib/api";
import { useAuth } from "../lib/auth";

const WARN_MS = 5 * 60_000;

export function SessionWarning() {
  const { me, adopt } = useAuth();
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 15_000); return () => clearInterval(t); }, []);
  if (!me || isDemoTransport()) return null;
  const idleEnd = lastActivityAt + (me.session.idle_minutes ?? 480) * 60_000;
  const hardEnd = new Date(me.session.absolute_expires_at).getTime();
  const end = Math.min(idleEnd, hardEnd);
  const left = end - now;
  if (left > WARN_MS || left <= 0) return null;
  const hard = hardEnd <= idleEnd;
  const mins = Math.max(1, Math.round(left / 60_000));
  return (
    <div role="status" className="flex flex-wrap items-center justify-center gap-3 border-b border-amber-400/30 bg-amber-400/10 px-4 py-2 text-[12.5px] text-amber-100 lg:ml-60">
      <TimerReset className="h-4 w-4" />
      {hard ? <>Your session reaches its maximum lifetime in about {mins} min. Save your work; you will need to sign in again.</>
        : <>You will be signed out in about {mins} min due to inactivity.</>}
      {!hard && <button className="rounded-md bg-amber-400/20 px-2.5 py-1 font-medium hover:bg-amber-400/30" onClick={async () => adopt(await api.me())}>Stay signed in</button>}
    </div>
  );
}
