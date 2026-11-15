import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmButton, PromptDialog } from "../components/ui";

describe("ConfirmButton", () => {
  it("runs the action only after explicit confirmation, and moves focus into the dialog", () => {
    const onConfirm = vi.fn();
    render(<ConfirmButton label="Disable" title="Disable user?" body="They will be signed out." confirmLabel="Disable account" onConfirm={onConfirm} />);
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onConfirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    fireEvent.click(screen.getByRole("button", { name: "Disable account" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

describe("PromptDialog", () => {
  it("refuses empty input when required and submits trimmed text", () => {
    const onSubmit = vi.fn();
    render(<PromptDialog open title="Save view" label="Filter name" onSubmit={onSubmit} onClose={() => undefined} />);
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "  Critical mine  " } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSubmit).toHaveBeenCalledWith("Critical mine");
  });
});
