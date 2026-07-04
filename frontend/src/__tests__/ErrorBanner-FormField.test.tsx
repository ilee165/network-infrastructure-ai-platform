/**
 * Tests for ErrorBanner (ApiError-aware panel error) and FormField
 * (label/control association), audit UI_UX #3 / #5.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { ErrorBanner } from "../components/ErrorBanner";
import { FormField } from "../components/FormField";

describe("ErrorBanner", () => {
  it("renders the RFC 7807 detail message for an ApiError", () => {
    const error = new ApiError({
      type: "urn:netops:error:not-found",
      title: "Not Found",
      status: 404,
      detail: "Device abc123 was not found.",
    });
    render(<ErrorBanner error={error} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Device abc123 was not found.");
  });

  it("falls back to error.message for a plain Error", () => {
    render(<ErrorBanner error={new Error("network timeout")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("network timeout");
  });

  it("renders a generic message for an unknown thrown value", () => {
    render(<ErrorBanner error="just a string" />);
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong.");
  });

  it("uses the panel/status-error idiom", () => {
    render(<ErrorBanner error={new Error("x")} data-testid="banner" />);
    expect(screen.getByTestId("banner")).toHaveClass(
      "panel",
      "border-status-error/40",
      "text-status-error",
    );
  });
});

describe("FormField", () => {
  it("associates the label with the control via a generated id", () => {
    render(
      <FormField label="Username">
        {(controlProps) => <input {...controlProps} type="text" />}
      </FormField>,
    );
    const input = screen.getByLabelText("Username");
    expect(input).toBeInTheDocument();
  });

  it("wires aria-invalid and aria-describedby to the error text when an error is present", () => {
    render(
      <FormField label="Username" error="Username is required">
        {(controlProps) => <input {...controlProps} type="text" />}
      </FormField>,
    );
    const input = screen.getByLabelText("Username");
    expect(input).toHaveAttribute("aria-invalid", "true");
    const describedBy = input.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    const errorNode = document.getElementById(describedBy as string);
    expect(errorNode).toHaveTextContent("Username is required");
  });

  it("does not set aria-invalid/aria-describedby when there is no error", () => {
    render(
      <FormField label="Username">
        {(controlProps) => <input {...controlProps} type="text" />}
      </FormField>,
    );
    const input = screen.getByLabelText("Username");
    expect(input).not.toHaveAttribute("aria-invalid");
    expect(input).not.toHaveAttribute("aria-describedby");
  });

  it("renders a required marker when required is set", () => {
    render(
      <FormField label="Username" required>
        {(controlProps) => <input {...controlProps} type="text" />}
      </FormField>,
    );
    expect(screen.getByText("*")).toBeInTheDocument();
  });
});
