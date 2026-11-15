// Case workflow metadata, mirrored from backend/app/cases.py for *display only*: the UI offers the
// transitions the server would accept, but the server re-checks every one of them.

export const STATUS_META: Record<string, { label: string; tone: string; help: string }> = {
  new: { label: "New", tone: "bg-sky-500/15 text-sky-200 ring-sky-500/40", help: "Created by correlation; nobody has looked yet" },
  triaged: { label: "Triaged", tone: "bg-violet-500/15 text-violet-200 ring-violet-500/40", help: "Confirmed worth investigating" },
  investigating: { label: "Investigating", tone: "bg-amber-500/15 text-amber-200 ring-amber-500/40", help: "An analyst is working the case" },
  awaiting_review: { label: "Awaiting review", tone: "bg-fuchsia-500/15 text-fuchsia-200 ring-fuchsia-500/40", help: "Waiting for the assigned reviewer" },
  resolved: { label: "Resolved", tone: "bg-emerald-500/15 text-emerald-200 ring-emerald-500/40", help: "Conclusion reached and reviewed" },
  closed: { label: "Closed", tone: "bg-ink-700 text-fg-muted ring-ink-600", help: "Reported and archived; evidence is preserved" },
};

export const TRANSITIONS: Record<string, string[]> = {
  new: ["triaged", "investigating"],
  triaged: ["investigating", "resolved"],
  investigating: ["awaiting_review", "resolved"],
  awaiting_review: ["investigating", "resolved"],
  resolved: ["closed", "investigating"],
  closed: ["investigating"],
};

export const ACTION_LABEL = (from: string, to: string): string => {
  if (to === "investigating" && (from === "resolved" || from === "closed")) return "Reopen";
  if (to === "investigating" && from === "awaiting_review") return "Send back";
  if (to === "investigating") return "Start investigating";
  if (to === "awaiting_review") return "Request review";
  if (to === "resolved" && from === "awaiting_review") return "Approve & resolve";
  return { triaged: "Mark triaged", resolved: "Resolve", closed: "Close" }[to] ?? to;
};

export const RESOLUTIONS = [
  { value: "true_positive", label: "True positive: malicious activity confirmed" },
  { value: "benign_true_positive", label: "Benign true positive: real activity, authorised" },
  { value: "false_positive", label: "False positive: detection was wrong" },
  { value: "duplicate", label: "Duplicate of another case" },
  { value: "unspecified", label: "Other / unspecified" },
];

export const PRIORITY_META: Record<string, { label: string; tone: string }> = {
  P1: { label: "P1 · urgent", tone: "text-rose-300" },
  P2: { label: "P2 · high", tone: "text-orange-300" },
  P3: { label: "P3 · normal", tone: "text-sky-300" },
  P4: { label: "P4 · low", tone: "text-fg-muted" },
};

export const ACTIVITY_LABEL: Record<string, string> = {
  "case.status_changed": "changed status", "case.reopened": "reopened the case", "case.updated": "updated the case",
  "comment.added": "commented", "note.added": "added a note", "comment.edited": "edited a comment", "note.edited": "edited a note",
  "comment.deleted": "deleted a comment", "note.deleted": "deleted a note", "evidence.pinned": "pinned evidence",
  "evidence.unpinned": "unpinned evidence", "analysis.created": "generated an AI analysis", "analysis.approved": "approved the analysis",
  "analysis.rejected": "rejected the analysis", "claim.accepted": "accepted a claim", "claim.rejected": "rejected a claim",
  "claim.pending": "reset a claim review", "investigation.exported": "exported the case", "investigation.updated": "updated the case (v1)",
};
