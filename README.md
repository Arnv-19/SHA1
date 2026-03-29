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

## Requirements

- Python 3.x
- Tkinter (standard with most Python installations)

No third-party cryptographic libraries are required.

## How to Run

1. **Start the Server**
   Open a terminal and run the server application:
   ```bash
   python sha1_attack/server.py
   ```
   *The server window will open, showing the server's generated secret length and a log text area.*

2. **Start the Client**
   Open a second terminal and run the client application:
   ```bash
   python sha1_attack/client.py
   ```

## Demonstration Workflow

1. **Generate Original MAC**
   - Go to the **"Normal Client Mode"** tab in the client application.
   - Enter a simple message (e.g., "Hello Server!") and click **"Send to Server"**.
   - The server processes `SHA1(secret || message)` and returns the MAC and SHA-1 internals block statistics.
     <img width="1365" height="615" alt="image" src="https://github.com/user-attachments/assets/14dbccba-6488-44cc-b9f3-0ca04c93cb91" />

2. **Execute the Attack**
   - Switch to the **"Attacker Mode"** tab. The original message and MAC will auto-populate.
   - Enter your malicious extension string.
   - Select the brute-force range for the secret length (e.g., 1 to 32 bytes).
   - Click **"Perform Length Extension Attack"**.
   - The client will simulate the attack by iterating through the guessed secret lengths. It will properly pad the original message, set the initial SHA-1 internal registers (`h0-h4`) to the hex values of the originally intercepted MAC, and process the extension to forge the new MAC.
   - Once the guessed length matches the server's true secret length, the server will log `VERIFICATION -> ACCEPTED` and the client will display `[SUCCESS] Attack completed!`.
<img width="1364" height="709" alt="image" src="https://github.com/user-attachments/assets/bcbcc40f-de86-470a-aaa3-2a82c61bbaea" />

3. **Analyze the Internals**
   - Switch to the **"SHA Internals"** tab.
   - Review the step-by-step block processing. Observe how the final states (`h0-h4`) of the original MAC become the initial states of the attacker's customized SHA-1 process for the forged extension. You can also see the exact reconstruction of the NIST FIPS 180-4 padding in hex.
<img width="1365" height="719" alt="image" src="https://github.com/user-attachments/assets/f12f209d-9489-4c06-9af0-37368b1bf26e" />

## Educational Purpose

This project explicitly illustrates the vulnerability of `Hash(secret || message)` constructions and why HMAC (Hash-based Message Authentication Code) is the standard defense against length extension attacks.
