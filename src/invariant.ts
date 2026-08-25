/**
 * Invariant companion for the bundle manifest. The redteam domain enforces
 * its record relationships at write time (store reference checks) and the
 * projection mirrors them by replaying logged calls; there is no additional
 * cross-service relation this entry could assert at load.
 *
 * No runtime invariant: referential integrity is owned by EngagementStore,
 * projection parity is covered by tests/projection.spec.ts.
 */

export function apply(): void {}
