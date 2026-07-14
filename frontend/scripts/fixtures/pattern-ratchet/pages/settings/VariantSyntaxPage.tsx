const classes = (...tokens: string[]) => tokens.join(" ");

export function VariantSyntaxPageFixture() {
  return (
    <>
      <div data-testid="variant-table" className={classes("overflow-x-auto", "panel")}>
        <table />
      </div>
      <div className="panel border-dashed" data-testid="variant-empty-state" />
      <div className="border-status-error/40 panel" role="alert" />
    </>
  );
}
