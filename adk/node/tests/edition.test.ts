/**
 * ZAK Edition Tests
 *
 * Covers:
 * - Default edition is open-source
 * - ZAK_EDITION=enterprise returns enterprise
 * - ZAK_EDITION=ent returns enterprise
 * - isEnterprise() works correctly
 * - EditionError class
 * - Edition constants
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  Edition,
  getEdition,
  isEnterprise,
  EditionError,
} from "../src/core/edition.js";

// ---------------------------------------------------------------------------
// Save and restore environment
// ---------------------------------------------------------------------------
let originalEdition: string | undefined;

beforeEach(() => {
  originalEdition = process.env.ZAK_EDITION;
});

afterEach(() => {
  if (originalEdition === undefined) {
    delete process.env.ZAK_EDITION;
  } else {
    process.env.ZAK_EDITION = originalEdition;
  }
});

// ---------------------------------------------------------------------------
// Edition constants
// ---------------------------------------------------------------------------
describe("Edition constants", () => {
  it("OPEN_SOURCE is 'open-source'", () => {
    expect(Edition.OPEN_SOURCE).toBe("open-source");
  });

  it("ENTERPRISE is 'enterprise'", () => {
    expect(Edition.ENTERPRISE).toBe("enterprise");
  });
});

// ---------------------------------------------------------------------------
// Default edition is open-source
// ---------------------------------------------------------------------------
describe("Default edition", () => {
  it("returns open-source when ZAK_EDITION is not set", () => {
    delete process.env.ZAK_EDITION;
    expect(getEdition()).toBe(Edition.OPEN_SOURCE);
  });

  it("returns open-source when ZAK_EDITION is empty string", () => {
    process.env.ZAK_EDITION = "";
    // Empty string will be treated as the default by the trim/check logic
    // The code does: (process.env.ZAK_EDITION ?? "open-source").toLowerCase().trim()
    // "" !== "enterprise" and "" !== "ent", so it falls through to open-source
    expect(getEdition()).toBe(Edition.OPEN_SOURCE);
  });

  it("returns open-source for unrecognized value", () => {
    process.env.ZAK_EDITION = "community";
    expect(getEdition()).toBe(Edition.OPEN_SOURCE);
  });

  it("returns open-source for 'open-source' value", () => {
    process.env.ZAK_EDITION = "open-source";
    expect(getEdition()).toBe(Edition.OPEN_SOURCE);
  });
});

// ---------------------------------------------------------------------------
// ZAK_EDITION=enterprise returns enterprise
// ---------------------------------------------------------------------------
describe("Enterprise edition via ZAK_EDITION=enterprise", () => {
  it("returns enterprise when ZAK_EDITION=enterprise", () => {
    process.env.ZAK_EDITION = "enterprise";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION=Enterprise (case-insensitive)", () => {
    process.env.ZAK_EDITION = "Enterprise";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION=ENTERPRISE (uppercase)", () => {
    process.env.ZAK_EDITION = "ENTERPRISE";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION has leading/trailing spaces", () => {
    process.env.ZAK_EDITION = "  enterprise  ";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });
});

// ---------------------------------------------------------------------------
// ZAK_EDITION=ent returns enterprise
// ---------------------------------------------------------------------------
describe("Enterprise edition via ZAK_EDITION=ent", () => {
  it("returns enterprise when ZAK_EDITION=ent", () => {
    process.env.ZAK_EDITION = "ent";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION=ENT (uppercase)", () => {
    process.env.ZAK_EDITION = "ENT";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION=Ent (mixed case)", () => {
    process.env.ZAK_EDITION = "Ent";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });

  it("returns enterprise when ZAK_EDITION=ent with whitespace", () => {
    process.env.ZAK_EDITION = " ent ";
    expect(getEdition()).toBe(Edition.ENTERPRISE);
  });
});

// ---------------------------------------------------------------------------
// isEnterprise() works
// ---------------------------------------------------------------------------
describe("isEnterprise()", () => {
  it("returns false when edition is open-source", () => {
    delete process.env.ZAK_EDITION;
    expect(isEnterprise()).toBe(false);
  });

  it("returns true when ZAK_EDITION=enterprise", () => {
    process.env.ZAK_EDITION = "enterprise";
    expect(isEnterprise()).toBe(true);
  });

  it("returns true when ZAK_EDITION=ent", () => {
    process.env.ZAK_EDITION = "ent";
    expect(isEnterprise()).toBe(true);
  });

  it("returns false for random value", () => {
    process.env.ZAK_EDITION = "pro";
    expect(isEnterprise()).toBe(false);
  });

  it("returns false for 'open-source'", () => {
    process.env.ZAK_EDITION = "open-source";
    expect(isEnterprise()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// EditionError
// ---------------------------------------------------------------------------
describe("EditionError", () => {
  it("is an instance of Error", () => {
    const err = new EditionError("Feature X requires enterprise");
    expect(err).toBeInstanceOf(Error);
  });

  it("is an instance of EditionError", () => {
    const err = new EditionError("Feature X requires enterprise");
    expect(err).toBeInstanceOf(EditionError);
  });

  it("has the correct name", () => {
    const err = new EditionError("Test");
    expect(err.name).toBe("EditionError");
  });

  it("preserves the error message", () => {
    const msg = "Feature 'advanced-analytics' requires ZAK Enterprise edition";
    const err = new EditionError(msg);
    expect(err.message).toBe(msg);
  });

  it("has a stack trace", () => {
    const err = new EditionError("Test");
    expect(err.stack).toBeTruthy();
    expect(err.stack).toContain("EditionError");
  });

  it("can be thrown and caught", () => {
    expect(() => {
      throw new EditionError("Not available in OSS");
    }).toThrow(EditionError);
  });

  it("can be caught with specific message check", () => {
    expect(() => {
      throw new EditionError("Enterprise only feature");
    }).toThrow("Enterprise only feature");
  });
});
