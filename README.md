## Demonstration Workflow

1. **Generate Original MAC**
   - Go to the **"Normal Client Mode"** tab in the client application.
   - Enter a simple message (e.g., "Hello Server!") and click **"Send to Server"**.
   - The server processes `SHA1(secret || message)` and returns the MAC and SHA-1 internals block statistics.

2. **Execute the Attack**
   - Switch to the **"Attacker Mode"** tab. The original message and MAC will auto-populate.
   - Enter your malicious extension string.
   - Select the brute-force range for the secret length (e.g., 1 to 32 bytes).
   - Click **"Perform Length Extension Attack"**.
   - The client will simulate the attack by iterating through the guessed secret lengths. It will properly pad the original message, set the initial SHA-1 internal registers (`h0-h4`) to the hex values of the originally intercepted MAC, and process the extension to forge the new MAC.
   - Once the guessed length matches the server's true secret length, the server will log `VERIFICATION -> ACCEPTED` and the client will display `[SUCCESS] Attack completed!`.

3. **Analyze the Internals**
   - Switch to the **"SHA Internals"** tab.
   - Review the step-by-step block processing. Observe how the final states (`h0-h4`) of the original MAC become the initial states of the attacker's customized SHA-1 process for the forged extension. You can also see the exact reconstruction of the NIST FIPS 180-4 padding in hex.

## Educational Purpose

This project explicitly illustrates the vulnerability of `Hash(secret || message)` constructions and why HMAC (Hash-based Message Authentication Code) is the standard defense against length extension attacks.

---

## 🛡️ The 4 Architectures Analyzed (Mitigation Suite)

To evaluate the mathematical and engineering trade-offs used to fix this vulnerability, this project includes a comparative testing engine (`review2_4way.py`) to benchmark the vulnerable baseline against three distinct mathematical defense mechanisms:

1. **The Baseline: Raw SHA-1 (Vulnerable)**
   - **Formula:** `MAC = H(K || M)`
   - **Status:** 100% Vulnerable. Because Merkle-Damgård hash functions output their exact final internal state, an attacker can use the intercepted signature as an Initialization Vector (IV) and append malicious data.

2. **Standard HMAC (Secure but Slowest)**
   - **Formula:** `HMAC = H((K ⊕ opad) || H((K ⊕ ipad) || M))`
   - **Status:** 0% Vulnerable. The industry standard double-nested hashing structure securely seals the internal state. However, padding the keys and hashing twice incurs the highest computational latency.

3. **Sandwich MAC (Secure and Fast)**
   - **Formula:** `SandwichMAC = H(K_front || M || K_back)`
   - **Status:** 0% Vulnerable. A high-speed experimental alternative. The secret key is bisected and placed at both the start and end of the payload. Any length extension attempt misaligns the trailing key during server verification, resulting in immediate rejection. 

4. **Double Hash MAC (Secure and Medium Speed)**
   - **Formula:** `DoubleHash = H(H(K || M))`
   - **Status:** 0% Vulnerable. The system generates the vulnerable naive MAC, but immediately hashes that output a second time before transmitting. Because hash functions are pre-image resistant, the attacker cannot reverse the final signature.

## 📊 4-Way Mitigation Dashboard

To run the automated analytical suite and view the real-time graphs:

1. Open a terminal and run the testing engine:
   ```bash
   python review2_4way.py
   ```
   
2. A GUI will launch. Interact with the buttons in sequential order (1 through 4) to generate 30 randomized payloads, execute the attack, test all three mitigations, and render the graphical dashboard.

3. The resulting Matplotlib dashboard will display four charts:
   - **Vulnerability Rate:** Proves SHA-1 fails (100%), while the three mitigations block the attack (0%).
   - **Time vs. Message Size:** Demonstrates linear scaling across all architectures.
   - **Integrity Preservation:** Evaluates the system's ability to reject tampered payloads.
   - **Latency Overhead Comparison:** Visualizes the precise computational penalty (in milliseconds) required to secure the system using HMAC, Sandwich MAC, and Double Hash MAC.
