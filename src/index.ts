/**
 * Bundle entry. The bundle's rows all resolve to package subpaths
 * (`./redteam`, `./storage-sqlite`, `./preset-root`, `./ui`); this root entry
 * exists so the manifest's `main` import target is valid and carries no
 * runtime behavior by design.
 */

export function apply(): void {}
