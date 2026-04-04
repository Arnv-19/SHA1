# SHA-1 Length Extension Attack Simulation

This project is a Python 3 application that demonstrates a **SHA-1 Length Extension Attack**. It features a complete client-server architecture, a Tkinter GUI to visualize the attack interactively, and a clean, step-by-step mathematical implementation of the SHA-1 logic adhering to NIST FIPS 180-4.

## Overview

The application simulates a scenario where a server authenticates messages using a Message Authentication Code (MAC) generated with a secret key (`MAC = SHA1(secret || message)`). An attacker, without knowing the secret key, can intercept the message and MAC, append malicious data to the message, and forge a valid MAC for the extended message.

### Core Components

- **`sha1.py`**: A manual Python implementation of the SHA-1 algorithm. This custom implementation is crucial because standard libraries (like `hashlib`) do not allow extracting or setting the internal state (h0-h4 registers), nor processing raw chunks, which are required to perform a length extension attack. It also records the block-processing history for visualization.

- **`server.py`**: A Tkinter-based TCP server listening on `localhost:5000`. It maintains a randomly generated secret key. It computes the MAC of incoming data and verifies whether client-submitted MACs match its own computation.

- **`client.py`**: A multi-tab Tkinter client application:
  - **Normal Client Mode**: Acts as a legitimate user requesting a MAC for a message.
  - **Attacker Mode**: Uses the intercepted original message and MAC to append an extension string (e.g., `...malicious payload...`). It brute-forces the server's secret length, pads the message correctly based on the guessed length, sets the custom SHA-1 state from the original MAC, hashes the extension, and sends the forged message and MAC to the server.
  - **SHA Internals**: Provides educational visualizations of the hashing process, dumping the 512-bit blocks, input lengths, reconstructed padding, and initial/final states of the SHA-1 registers per block.

- **`review2_4way.py`**: *(New Mitigation Suite)* An automated 4-way testing engine and Tkinter/Matplotlib dashboard. It runs 30 randomized computational iterations to benchmark the vulnerability rate, system integrity, and latency overhead of four different MAC architectures.

## Requirements

- Python 3.x
- Tkinter (standard with most Python installations)
- Matplotlib (Required for the 4-Way Analytical Dashboard: `pip install matplotlib`)

*No third-party cryptographic libraries are required.*

## How to Run

1. **Start the Server**
   Open a terminal and run the server application:
   ```bash
   python sha1_attack/server.py

The server window will open, showing the server's generated secret length and a log text area.

Start the Client
Open a second terminal and run the client application:
python sha1_attack/client.py

Demonstration Workflow
Generate Original MAC

Go to the "Normal Client Mode" tab in the client application.

Enter a simple message (e.g., "Hello Server!") and click "Send to Server".

The server processes SHA1(secret || message) and returns the MAC and SHA-1 internals block statistics.

Execute the Attack

Switch to the "Attacker Mode" tab. The original message and MAC will auto-populate.

Enter your malicious extension string.

Select the brute-force range for the secret length (e.g., 1 to 32 bytes).

Click "Perform Length Extension Attack".

The client will simulate the attack by iterating through the guessed secret lengths. It will properly pad the original message, set the initial SHA-1 internal registers (h0-h4) to the hex values of the originally intercepted MAC, and process the extension to forge the new MAC.

Once the guessed length matches the server's true secret length, the server will log VERIFICATION -> ACCEPTED and the client will display [SUCCESS] Attack completed!.

Analyze the Internals

Switch to the "SHA Internals" tab.

Review the step-by-step block processing. Observe how the final states (h0-h4) of the original MAC become the initial states of the attacker's customized SHA-1 process for the forged extension. You can also see the exact reconstruction of the NIST FIPS 180-4 padding in hex.

Educational Purpose
This project explicitly illustrates the vulnerability of Hash(secret || message) constructions and why HMAC (Hash-based Message Authentication Code) is the standard defense against length extension attacks.

🛡️ The 4 Architectures Analyzed (Mitigation Suite)
To evaluate the mathematical and engineering trade-offs used to fix this vulnerability, this project includes a comparative testing engine (review2_4way.py) to benchmark the vulnerable baseline against three distinct mathematical defense mechanisms:

The Baseline: Raw SHA-1 (Vulnerable)

Formula: MAC = H(K || M)

Status: 100% Vulnerable. Because Merkle-Damgård hash functions output their exact final internal state, an attacker can use the intercepted signature as an Initialization Vector (IV) and append malicious data.

Standard HMAC (Secure but Slowest)

Formula: HMAC = H((K ⊕ opad) || H((K ⊕ ipad) || M))

Status: 0% Vulnerable. The industry standard double-nested hashing structure securely seals the internal state. However, padding the keys and hashing twice incurs the highest computational latency.

Sandwich MAC (Secure and Fast)

Formula: SandwichMAC = H(K_front || M || K_back)

Status: 0% Vulnerable. A high-speed experimental alternative. The secret key is bisected and placed at both the start and end of the payload. Any length extension attempt misaligns the trailing key during server verification, resulting in immediate rejection.

Double Hash MAC (Secure and Medium Speed)

Formula: DoubleHash = H(H(K || M))

Status: 0% Vulnerable. The system generates the vulnerable naive MAC, but immediately hashes that output a second time before transmitting. Because hash functions are pre-image resistant, the attacker cannot reverse the final signature.

📊 4-Way Mitigation Dashboard
To run the automated analytical suite and view the real-time graphs:

Open a terminal and run the testing engine:

Bash
python review2_4way.py
A GUI will launch. Interact with the buttons in sequential order (1 through 4) to generate 30 randomized payloads, execute the attack, test all three mitigations, and render the graphical dashboard.

The resulting Matplotlib dashboard will display four charts:

Vulnerability Rate: Proves SHA-1 fails (100%), while the three mitigations block the attack (0%).

Time vs. Message Size: Demonstrates linear scaling across all architectures.

Integrity Preservation: Evaluates the system's ability to reject tampered payloads.

Latency Overhead Comparison: Visualizes the precise computational penalty (in milliseconds) required to secure the system using HMAC, Sandwich MAC, and Double Hash MAC.
