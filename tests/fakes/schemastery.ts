/** Schemastery fake: chainable no-op builders for Config declarations. */

class FakeSchema {
  required(): FakeSchema { return this }
  default(_value: unknown): FakeSchema { return this }
  static object(_shape: Record<string, unknown>): FakeSchema { return new FakeSchema() }
  static string(): FakeSchema { return new FakeSchema() }
  static boolean(): FakeSchema { return new FakeSchema() }
  static number(): FakeSchema { return new FakeSchema() }
  static union<const Options extends readonly unknown[]>(_options: Options): FakeSchema { return new FakeSchema() }
  static dict(_schema?: FakeSchema): FakeSchema { return new FakeSchema() }
  static array(_schema?: FakeSchema): FakeSchema { return new FakeSchema() }
}

export default FakeSchema
