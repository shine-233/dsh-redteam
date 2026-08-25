/**
 * Narrow ambient surface of `@deepseek-ai/schemastery` (vendored upstream,
 * shipped to consumers via the npm package). The default export is a generic
 * schema class usable in BOTH positions, matching upstream plugin usage:
 * `export const Config: z<Config> = z.object({ ... })`.
 */

declare class z<T = unknown> {
  /** Phantom slot naming the parsed config type (`z<Config>` annotations). */
  readonly '~type'?: T | undefined
  required(): z<T>
  default(value: T): z<T>
  static object(shape: Record<string, z<any>>): z<any>
  static string(): z<string>
  static boolean(): z<boolean>
  static number(): z<number>
  static union<const Options extends readonly string[]>(options: Options): z<Options[number]>
  static dict(schema?: z<any>): z<Record<string, unknown>>
  static array(schema?: z<any>): z<any[]>
}

export default z
