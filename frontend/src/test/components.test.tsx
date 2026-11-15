// Component tests: badges and states render the right semantics.
import { render, screen } from "@testing-library/react";
import { VerdictBar } from "../components/AnalysisPanel";
import { EmptyState, ErrorState, SeverityBadge, VerdictBadge } from "../components/ui";
import { ApiError } from "../lib/api";

describe("ui primitives", () => {
  it("shows verdict labels with explanatory tooltip", () => {
    render(<VerdictBadge verdict="contradictory_finding" />);
    const el = screen.getByText("Contradictory finding");
    expect(el.closest("span")).toHaveAttribute("title", expect.stringContaining("evidence says otherwise"));
  });
  it("renders severity", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
  it("surfaces API error messages", () => {
    render(<ErrorState error={new ApiError(409, "every unsupported or contradictory claim must be reviewed first")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("must be reviewed first");
  });
  it("renders empty state", () => {
    render(<EmptyState title="Nothing here">hint</EmptyState>);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });
  it("verdict bar shows counts for each verdict", () => {
    render(<VerdictBar verdicts={{ verified_observation: 3, unsupported_claim: 1 }} />);
    expect(screen.getByText("Verified").parentElement).toHaveTextContent("3");
    expect(screen.getByText("Unsupported").parentElement).toHaveTextContent("1");
  });
});
