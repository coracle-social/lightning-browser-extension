import { base64 } from "@scure/base";
import { randomBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20 } from "@noble/ciphers/chacha";
import { schnorr } from "@noble/curves/secp256k1";
import * as secp256k1 from "@noble/secp256k1";
import { Buffer } from "buffer";
import * as CryptoJS from "crypto-js";
import { AES } from "crypto-js";
import Base64 from "crypto-js/enc-base64";
import Hex from "crypto-js/enc-hex";
import Utf8 from "crypto-js/enc-utf8";
import { LRUCache } from "~/common/utils/lruCache";
import { Event } from "~/extension/providers/nostr/types";

import { getEventHash, signEvent } from "../actions/nostr/helpers";

const utf8Decoder = new TextDecoder();

const utf8Encoder = new TextEncoder();

class Nostr {
  nip44SharedSecretCache = new LRUCache<string, Uint8Array>(100);

  constructor(readonly privateKey: string) {}

  // Deriving shared secret is an expensive computation
  getNip44SharedSecret(pk: string) {
    let key = this.nip44SharedSecretCache.get(pk);

    if (!key) {
      key = sha256(
        secp256k1.getSharedSecret(this.privateKey, "02" + pk).subarray(1, 33)
      );

      this.nip44SharedSecretCache.set(pk, key);
    }

    return key;
  }

  getPublicKey() {
    const publicKey = schnorr.getPublicKey(
      secp256k1.etc.hexToBytes(this.privateKey)
    );
    const publicKeyHex = secp256k1.etc.bytesToHex(publicKey);
    return publicKeyHex;
  }

  async signEvent(event: Event): Promise<Event> {
    const signature = await signEvent(event, this.privateKey);
    event.sig = signature;
    return event;
  }

  async signSchnorr(sigHash: string): Promise<string> {
    const signature = await schnorr.sign(
      Buffer.from(secp256k1.etc.hexToBytes(sigHash)),
      secp256k1.etc.hexToBytes(this.privateKey)
    );
    const signedHex = secp256k1.etc.bytesToHex(signature);
    return signedHex;
  }

  encrypt(pubkey: string, text: string) {
    const key = secp256k1.getSharedSecret(this.privateKey, "02" + pubkey);
    const normalizedKey = Buffer.from(key.slice(1, 33));
    const hexNormalizedKey = secp256k1.etc.bytesToHex(normalizedKey);
    const hexKey = Hex.parse(hexNormalizedKey);

    const encrypted = AES.encrypt(text, hexKey, {
      iv: CryptoJS.lib.WordArray.random(16),
    });

    return `${encrypted.toString()}?iv=${encrypted.iv.toString(
      CryptoJS.enc.Base64
    )}`;
  }

  async decrypt(pubkey: string, ciphertext: string) {
    const [cip, iv] = ciphertext.split("?iv=");
    const key = secp256k1.getSharedSecret(this.privateKey, "02" + pubkey);
    const normalizedKey = Buffer.from(key.slice(1, 33));
    const hexNormalizedKey = secp256k1.etc.bytesToHex(normalizedKey);
    const hexKey = Hex.parse(hexNormalizedKey);

    const decrypted = AES.decrypt(cip, hexKey, {
      iv: Base64.parse(iv),
    });

    return Utf8.stringify(decrypted);
  }

  nip44Encrypt(pubkey: string, text: string, v = 1) {
    if (v !== 1) {
      throw new Error("NIP44: unknown encryption version");
    }

    const nonce = randomBytes(24);
    const plaintext = utf8Encoder.encode(text);
    const key = this.getNip44SharedSecret(pubkey);
    const ciphertext = xchacha20(key, nonce, plaintext);

    const payload = new Uint8Array(25 + ciphertext.length);
    payload.set([v], 0);
    payload.set(nonce, 1);
    payload.set(ciphertext, 25);

    return base64.encode(payload);
  }

  nip44Decrypt(pubkey: string, payload: string) {
    let data;
    try {
      data = base64.decode(payload);
    } catch (e) {
      throw new Error(`NIP44: failed to base64 decode payload: ${e}`);
    }

    if (data[0] !== 1) {
      throw new Error(`NIP44: unknown encryption version: ${data[0]}`);
    }

    const nonce = data.slice(1, 25);
    const ciphertext = data.slice(25);
    const key = this.getNip44SharedSecret(pubkey);
    const plaintext = xchacha20(key, nonce, ciphertext);

    return utf8Decoder.decode(plaintext);
  }

  getEventHash(event: Event) {
    return getEventHash(event);
  }
}

export default Nostr;
