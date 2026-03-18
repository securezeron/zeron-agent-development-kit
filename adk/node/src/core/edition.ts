/**
 * ZAK Edition — runtime edition detection for open-source vs enterprise gating.
 *
 * Usage:
 *   import { getEdition, isEnterprise, Edition, EditionError } from './edition.js';
 *
 * Control via environment variable:
 *   ZAK_EDITION=open-source   (default)
 *   ZAK_EDITION=enterprise
 *
 * TypeScript equivalent of zak/core/edition.py.
 */

// ---------------------------------------------------------------------------
// Edition enum
// ---------------------------------------------------------------------------

export const Edition = {
  OPEN_SOURCE: "open-source",
  ENTERPRISE: "enterprise",
} as const;

export type Edition = (typeof Edition)[keyof typeof Edition];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Return the current edition based on the ZAK_EDITION environment variable.
 */
export function getEdition(): Edition {
  const val = (process.env.ZAK_EDITION ?? "open-source").toLowerCase().trim();
  if (val === "enterprise" || val === "ent") {
    return Edition.ENTERPRISE;
  }
  return Edition.OPEN_SOURCE;
}

/**
 * Return true if running under the enterprise edition.
 */
export function isEnterprise(): boolean {
  return getEdition() === Edition.ENTERPRISE;
}

// ---------------------------------------------------------------------------
// EditionError
// ---------------------------------------------------------------------------

/**
 * Raised when an enterprise-only feature is accessed on the open-source edition.
 */
export class EditionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EditionError";
  }
}
