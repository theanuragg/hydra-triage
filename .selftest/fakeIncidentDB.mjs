import { FakeGraph, startFakeHydraDB } from "./fakeHydraDB.mjs";

/**
 * The generic engine in fakeHydraDB.mjs is label- and property-driven, so
 * the incident selftest exercises the exact same handler code against the
 * Version/Consumer/DEPENDS_ON/RESOLVED schema. Keeping one engine (instead
 * of a second hand-written fake) means the two selftests can never silently
 * diverge in their understanding of HydraDB's protocol, the way two
 * shape-specific fakes could when each recognized only its own schema's
 * inlined UNWIND literals.
 */
export async function startFakeIncidentDB({ port = 0 } = {}) {
  return startFakeHydraDB(new FakeGraph(), { port });
}