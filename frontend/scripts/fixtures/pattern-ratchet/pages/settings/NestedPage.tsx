export function NestedPageFixture() {
  return (
    <>
      <div className="panel overflow-x-auto"><table /></div>
      <div data-testid="nested-empty-state" />
      <div role="alert" className="panel border-status-error/40" />
    </>
  );
}
