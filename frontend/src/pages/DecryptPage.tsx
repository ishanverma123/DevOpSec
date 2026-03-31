import { useState } from "react";

import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { EncryptionAlgorithm } from "../types";

const algorithms: EncryptionAlgorithm[] = [
  "aes-256-gcm",
  "des-ede3-cbc",
  "caesar",
  "substitution",
  "morse",
  "base64"
];

export default function DecryptPage() {
  const { token } = useAuth();
  const [payload, setPayload] = useState("");
  const [algorithm, setAlgorithm] = useState<EncryptionAlgorithm>("morse");
  const [iv, setIv] = useState("");
  const [authTag, setAuthTag] = useState("");
  const [plainText, setPlainText] = useState("");
  const [error, setError] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);

  const decrypt = async () => {
    setError("");
    setIsDecrypting(true);

    try {
      let encryptedValue = payload.trim();
      let selectedAlgorithm = algorithm;
      let selectedIv = iv.trim();
      let selectedAuthTag = authTag.trim();

      if (!encryptedValue) {
        throw new Error("Please enter cipher text or JSON payload");
      }

      if (encryptedValue.startsWith("{")) {
        const data = JSON.parse(encryptedValue) as {
          encrypted_value?: string;
          iv?: string;
          auth_tag?: string;
          encryption_algorithm?: EncryptionAlgorithm;
        };

        if (!data.encrypted_value) {
          throw new Error("JSON payload must include encrypted_value");
        }

        encryptedValue = data.encrypted_value;
        selectedAlgorithm = data.encryption_algorithm ?? selectedAlgorithm;
        selectedIv = data.iv ?? "";
        selectedAuthTag = data.auth_tag ?? "";
      }

      const result = await api.decryptCipher(token, {
        encryptedValue,
        iv: selectedIv,
        authTag: selectedAuthTag,
        algorithm: selectedAlgorithm
      });

      setPlainText(result.plainText);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decrypt failed");
    } finally {
      setIsDecrypting(false);
    }
  };

  return (
    <section className="module">
      <div className="module-top">
        <h3>Decrypt Workspace</h3>
      </div>
      <div className="input-row">
        <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as EncryptionAlgorithm)}>
          {algorithms.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <input value={iv} onChange={(e) => setIv(e.target.value)} placeholder="IV (optional for some algorithms)" />
        <input
          value={authTag}
          onChange={(e) => setAuthTag(e.target.value)}
          placeholder="Auth Tag (optional for some algorithms)"
        />
      </div>
      <textarea
        className="fixed-face"
        rows={12}
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        placeholder='Paste cipher text directly OR JSON {"encrypted_value":"...","iv":"...","auth_tag":"...","encryption_algorithm":"aes-256-gcm"}'
      />
      <button onClick={decrypt} disabled={isDecrypting}>
        {isDecrypting ? "Decrypting..." : "Decrypt Payload"}
      </button>
      {isDecrypting ? (
        <div className="loader-inline" role="status" aria-live="polite">
          <span className="loader-dot" />
          <p>Decrypting payload...</p>
        </div>
      ) : null}
      {error ? <p className="fail-text">{error}</p> : null}
      {plainText ? <pre className="plain-view fixed-face">{plainText}</pre> : null}
    </section>
  );
}
