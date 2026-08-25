/**
 * Host half of the Web surface row. The row must point at a Loader entry of
 * THIS package so the module scanner reads the bundle manifest's
 * `dsh.client` declaration and serves `./client`; the Node face registers
 * nothing — the browser half owns every slot contribution.
 */

export function apply(): void {}
