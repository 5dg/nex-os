import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";

const MAX_PLAINTEXT = 32 * 1024;
// Existing encrypted records remain nonce (12) + ciphertext + GCM tag (16).
// Keys are independent random secrets supplied by the trusted runtime; this
// helper does not provision keys or authorize a production profile.
export class SessionKeyring {
  readonly #current: Buffer;
  readonly #previous: Buffer | undefined;
  constructor(current: Uint8Array, previous?: Uint8Array) {
    const valid = (key: unknown): key is Uint8Array => key instanceof Uint8Array && key.length === 32 && !key.every(value => value === 0);
    if (!valid(current) || (previous !== undefined && (!valid(previous) || timingSafeEqual(Buffer.from(current), Buffer.from(previous))))) throw new Error("Session encryption keyring invalid");
    this.#current = Buffer.from(current);
    this.#previous = previous === undefined ? undefined : Buffer.from(previous);
  }
  seal(plaintext: Uint8Array, associatedData: Uint8Array): Buffer {
    if (plaintext.length > MAX_PLAINTEXT) throw new Error("Session payload exceeds limit");
    const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.#current, nonce);
    cipher.setAAD(associatedData);
    return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  }
  unseal(sealed: Uint8Array, associatedData: Uint8Array): Buffer {
    if (sealed.length < 28 || sealed.length > MAX_PLAINTEXT + 28) throw new Error("Session record invalid");
    const encoded = Buffer.from(sealed);
    const attempt = (key: Buffer): Buffer | undefined => {
      let partial: Buffer | undefined;
      try {
        const cipher = createDecipheriv("aes-256-gcm", key, encoded.subarray(0, 12));
        cipher.setAAD(associatedData); cipher.setAuthTag(encoded.subarray(encoded.length - 16));
        partial = cipher.update(encoded.subarray(12, -16));
        const result = Buffer.concat([partial, cipher.final()]);
        partial.fill(0);
        return result;
      } catch { partial?.fill(0); return undefined; }
    };
    const current = attempt(this.#current);
    // Try both configured keys before choosing a result; an ambiguous match
    // fails closed. Previous-key records are accepted only during explicit overlap.
    const previous = this.#previous ? attempt(this.#previous) : undefined;
    if ((!current && !previous) || (current && previous)) {
      current?.fill(0); previous?.fill(0);
      throw new Error("Session record invalid");
    }
    return (current || previous)!;
  }
}
