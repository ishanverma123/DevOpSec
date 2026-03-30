import crypto from "crypto";

import { env } from "../config/env";

export const SUPPORTED_ALGORITHMS = [
  "aes-256-gcm",
  "des-ede3-cbc",
  "caesar",
  "substitution",
  "morse",
  "base64"
] as const;

export type EncryptionAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

const AES_ALGORITHM = "aes-256-gcm";
const DES3_ALGORITHM = "des-ede3-cbc";
const MORSE_SEPARATOR = " / ";

const getAesKey = () => {
  return crypto.createHash("sha256").update(env.ENCRYPTION_KEY).digest();
};

const get3DesKey = () => {
  return crypto.createHash("sha256").update(env.TRIPLE_DES_KEY).digest().subarray(0, 24);
};

const MORSE_MAP: Record<string, string> = {
  a: ".-",
  b: "-...",
  c: "-.-.",
  d: "-..",
  e: ".",
  f: "..-.",
  g: "--.",
  h: "....",
  i: "..",
  j: ".---",
  k: "-.-",
  l: ".-..",
  m: "--",
  n: "-.",
  o: "---",
  p: ".--.",
  q: "--.-",
  r: ".-.",
  s: "...",
  t: "-",
  u: "..-",
  v: "...-",
  w: ".--",
  x: "-..-",
  y: "-.--",
  z: "--..",
  0: "-----",
  1: ".----",
  2: "..---",
  3: "...--",
  4: "....-",
  5: ".....",
  6: "-....",
  7: "--...",
  8: "---..",
  9: "----.",
  " ": MORSE_SEPARATOR
};

const REVERSE_MORSE_MAP = Object.fromEntries(
  Object.entries(MORSE_MAP).map(([k, v]) => [v, k])
);

const shiftChar = (char: string, shift: number) => {
  const code = char.charCodeAt(0);
  const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : -1;
  if (base === -1) {
    return char;
  }

  const normalized = code - base;
  const shifted = (normalized + shift + 26) % 26;
  return String.fromCharCode(base + shifted);
};

const caesarEncrypt = (plainText: string, shift = 3) => {
  return plainText
    .split("")
    .map((char) => shiftChar(char, shift))
    .join("");
};

const caesarDecrypt = (cipherText: string, shift = 3) => {
  return cipherText
    .split("")
    .map((char) => shiftChar(char, -shift))
    .join("");
};

const substitutionEncrypt = (plainText: string) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const key = env.SUBSTITUTION_KEY.toLowerCase();
  return plainText
    .split("")
    .map((char) => {
      const lower = char.toLowerCase();
      const index = alphabet.indexOf(lower);
      if (index === -1) {
        return char;
      }

      const mapped = key[index];
      return char === lower ? mapped : mapped.toUpperCase();
    })
    .join("");
};

const substitutionDecrypt = (cipherText: string) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const key = env.SUBSTITUTION_KEY.toLowerCase();
  return cipherText
    .split("")
    .map((char) => {
      const lower = char.toLowerCase();
      const index = key.indexOf(lower);
      if (index === -1) {
        return char;
      }

      const mapped = alphabet[index];
      return char === lower ? mapped : mapped.toUpperCase();
    })
    .join("");
};

const morseEncrypt = (plainText: string) => {
  return plainText
    .toLowerCase()
    .split("")
    .map((char) => MORSE_MAP[char] ?? char)
    .join(" ");
};

const morseDecrypt = (cipherText: string) => {
  return cipherText
    .split(" ")
    .map((code) => REVERSE_MORSE_MAP[code] ?? code)
    .join("")
    .split(MORSE_SEPARATOR)
    .join(" ");
};

type EncryptResult = {
  encryptedValue: string;
  iv: string;
  authTag: string;
  algorithm: EncryptionAlgorithm;
};

export const encryptSecret = (
  plainText: string,
  algorithm: EncryptionAlgorithm = "aes-256-gcm"
): EncryptResult => {
  if (algorithm === "aes-256-gcm") {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, getAesKey(), iv);

    const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      encryptedValue: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm
    };
  }

  if (algorithm === "des-ede3-cbc") {
    const iv = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv(DES3_ALGORITHM, get3DesKey(), iv);
    const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
    return {
      encryptedValue: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: "",
      algorithm
    };
  }

  if (algorithm === "caesar") {
    return {
      encryptedValue: caesarEncrypt(plainText),
      iv: "-",
      authTag: "-",
      algorithm
    };
  }

  if (algorithm === "substitution") {
    return {
      encryptedValue: substitutionEncrypt(plainText),
      iv: "-",
      authTag: "-",
      algorithm
    };
  }

  if (algorithm === "morse") {
    return {
      encryptedValue: morseEncrypt(plainText),
      iv: "-",
      authTag: "-",
      algorithm
    };
  }

  return {
    encryptedValue: Buffer.from(plainText, "utf8").toString("base64"),
    iv: "-",
    authTag: "-",
    algorithm: "base64"
  };
};

export const decryptSecret = (
  encryptedValue: string,
  iv: string,
  authTag: string,
  algorithm: EncryptionAlgorithm = "aes-256-gcm"
) => {
  if (algorithm === "aes-256-gcm") {
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, getAesKey(), Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(authTag, "base64"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedValue, "base64")),
      decipher.final()
    ]);
    return decrypted.toString("utf8");
  }

  if (algorithm === "des-ede3-cbc") {
    const decipher = crypto.createDecipheriv(DES3_ALGORITHM, get3DesKey(), Buffer.from(iv, "base64"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedValue, "base64")),
      decipher.final()
    ]);
    return decrypted.toString("utf8");
  }

  if (algorithm === "caesar") {
    return caesarDecrypt(encryptedValue);
  }

  if (algorithm === "substitution") {
    return substitutionDecrypt(encryptedValue);
  }

  if (algorithm === "morse") {
    return morseDecrypt(encryptedValue);
  }

  return Buffer.from(encryptedValue, "base64").toString("utf8");
};
