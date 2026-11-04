// Client entry point: renders the placeholder page into `#app`.
//
// Security: the DOM is built only with createElement/textContent, never innerHTML or
// other HTML sinks; the CSP's `require-trusted-types-for 'script'` makes any such sink
// throw at runtime.

/**
 * Replaces the contents of `root` with the placeholder page.
 *
 * @example
 * renderPlaceholder(document.getElementById("app")!);
 */
function renderPlaceholder(root: HTMLElement): void {
  const heading = document.createElement("h1");
  heading.textContent = "Secure Pass Manager";
  const note = document.createElement("p");
  note.textContent = "The web client is under construction.";
  root.replaceChildren(heading, note);
}

const root = document.getElementById("app");
if (root !== null) {
  renderPlaceholder(root);
}
