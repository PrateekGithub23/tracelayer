// Unit tests for formatting helpers and semantic maps.
import { fmtBytes, fmtMs, fmtTime, UNSAFE, VERDICT_META, VERDICTS } from "../lib/format";

describe("format helpers", () => {
  it("formats bytes with binary units", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(1536)).toBe("1.5 KB");
    expect(fmtBytes(24 * 16 * 1024 * 1024)).toBe("384 MB");
  });
  it("formats durations across scales", () => {
    expect(fmtMs(0.25)).toBe("250 µs");
    expect(fmtMs(42)).toBe("42 ms");
    expect(fmtMs(2500)).toBe("2.50 s");
  });
  it("renders timestamps in UTC", () => {
    expect(fmtTime("2026-11-03T11:09:00Z")).toBe("2026-11-03 11:09:00");
  });
  it("has metadata for every verdict and marks exactly two as unsafe", () => {
    expect(VERDICTS.every((v) => VERDICT_META[v].label)).toBe(true);
    expect(UNSAFE).toEqual(["unsupported_claim", "contradictory_finding"]);
  });
});
