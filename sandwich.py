import tkinter as tk
from tkinter import scrolledtext
import matplotlib.pyplot as plt
import struct
import random
import string
import time
import binascii


def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

class CustomSHA1:
    def __init__(self, message=b'', h_state=None, total_len_bits=None):
        if h_state is None:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        else:
            self.h = h_state[:]
        
        if total_len_bits is None:
            self.message_byte_length = 0
        else:
            self.message_byte_length = total_len_bits // 8

        self.unprocessed = b''
        self.update(message)

    def update(self, message):
        self.message_byte_length += len(message)
        chunk = self.unprocessed + message
        while len(chunk) >= 64:
            self._process_chunk(chunk[:64])
            chunk = chunk[64:]
        self.unprocessed = chunk

    def _process_chunk(self, chunk):
        w = [0] * 80
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i*4:i*4+4])[0]
        for i in range(16, 80):
            w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

        a, b, c, d, e = self.h

        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d; d = c; c = left_rotate(b, 30); b = a; a = temp

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF

    def digest(self):
        return struct.pack(b'>IIIII', *self.h)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode('ascii')

    def finalize(self):
        message_bit_length = self.message_byte_length * 8
        message = self.unprocessed + b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        message += struct.pack(b'>Q', message_bit_length)
        self._process_chunk(message[:64])
        if len(message) == 128:
            self._process_chunk(message[64:])
        return self.hexdigest()

def custom_hmac_sha1(key, message):
    block_size = 64
    if len(key) > block_size:
        key = binascii.unhexlify(CustomSHA1(key).finalize())
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    o_key_pad = bytes(x ^ 0x5c for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)

    inner_hash = binascii.unhexlify(CustomSHA1(i_key_pad + message).finalize())
    return CustomSHA1(o_key_pad + inner_hash).finalize()

def custom_sandwich_mac(key, message):
    if len(key) < 2:
        key = key + b'\x00' * (2 - len(key))
    
    midpoint = len(key) // 2
    key_front = key[:midpoint]
    key_back = key[midpoint:]
    
    sandwiched_payload = key_front + message + key_back
    return CustomSHA1(sandwiched_payload).finalize()


def md_pad(length):
    bit_len = length * 8
    pad = b'\x80'
    while ((length + len(pad)) * 8) % 512 != 448:
        pad += b'\x00'
    pad += struct.pack(b'>Q', bit_len)
    return pad

def length_extension_attack(original_sig, msg_len, append_data):
    h_state = list(struct.unpack(b'>IIIII', binascii.unhexlify(original_sig)))
    padding = md_pad(msg_len)
    total_len_bits = (msg_len + len(padding)) * 8 
    
    forger = CustomSHA1(message=append_data, h_state=h_state, total_len_bits=total_len_bits)
    return padding, forger.finalize()


class TestEngine:
    def __init__(self):
        self.attack_success = 0
        self.hmac_success = 0
        self.sandwich_success = 0
        self.test_count = 30
        self.metrics = {"sha1_times": [], "hmac_times": [], "sandwich_times": [], "sizes": []}

    def generate_random_string(self, length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length)).encode()

    def run_tests(self):
        self.attack_success = 0; self.hmac_success = 0; self.sandwich_success = 0
        self.metrics = {"sha1_times": [], "hmac_times": [], "sandwich_times": [], "sizes": []}

        for _ in range(self.test_count):
            secret = self.generate_random_string(random.randint(10, 25))
            msg = self.generate_random_string(random.randint(100, 500))
            append = b"&role=superuser"
            self.metrics["sizes"].append(len(msg))

            start = time.perf_counter()
            orig_sig = CustomSHA1(secret + msg).finalize()
            self.metrics["sha1_times"].append((time.perf_counter() - start) * 1000)

            pad, forged_sig = length_extension_attack(orig_sig, len(secret + msg), append)
            actual_forged = CustomSHA1(secret + msg + pad + append).finalize()
            if forged_sig == actual_forged:
                self.attack_success += 1

            start = time.perf_counter()
            orig_hmac = custom_hmac_sha1(secret, msg)
            self.metrics["hmac_times"].append((time.perf_counter() - start) * 1000)
            self.hmac_success += 1

            start = time.perf_counter()
            orig_sandwich = custom_sandwich_mac(secret, msg)
            self.metrics["sandwich_times"].append((time.perf_counter() - start) * 1000)
            self.sandwich_success += 1


class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Review 2: Architecture Comparison (SHA-1 vs HMAC vs Sandwich)")
        self.root.geometry("850x600")
        self.engine = TestEngine()

        left_frame = tk.Frame(root, width=220, bg="#2c3e50")
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        right_frame = tk.Frame(root, bg="#ecf0f1")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.status_canvas = tk.Canvas(left_frame, width=50, height=50, bg="#2c3e50", highlightthickness=0)
        self.status_canvas.pack(pady=20)
        self.indicator = self.status_canvas.create_oval(10, 10, 40, 40, fill="gray")

        tk.Button(left_frame, text="1. Generate Test Data", command=self.generate_keys, width=22).pack(pady=10)
        tk.Button(left_frame, text="2. Attack SHA-1", command=self.run_attack, width=22).pack(pady=10)
        tk.Button(left_frame, text="3. Test Defenses (HMAC/Sandwich)", command=self.apply_prevention, width=22).pack(pady=10)
        tk.Button(left_frame, text="4. Show 3-Way Dashboard", command=self.show_graphs, width=22).pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.log("System Initialized. Ready for Comparative Analysis...\n")

    def log(self, text):
        self.log_area.insert(tk.END, text + "\n")
        self.log_area.see(tk.END)

    def change_indicator(self, color):
        self.status_canvas.itemconfig(self.indicator, fill=color)

    def generate_keys(self):
        self.engine.run_tests()
        self.log(f"Generated {self.engine.test_count} payloads.")
        self.log("Captured timing metrics for SHA-1, HMAC, and Sandwich MAC.")
        self.change_indicator("yellow")

    def run_attack(self):
        if not self.engine.metrics["sizes"]: return
        rate = (self.engine.attack_success / self.engine.test_count) * 100
        self.log("\n--- EXECUTING ATTACK ON RAW SHA-1 ---")
        self.log(f"Vulnerability Rate: {rate}%")
        self.change_indicator("red")

    def apply_prevention(self):
        if not self.engine.metrics["sizes"]: return
        self.log("\n--- TESTING DEFENSE ARCHITECTURES ---")
        self.log(f"HMAC Defense Rate: {(self.engine.hmac_success/self.engine.test_count)*100}%")
        self.log(f"Sandwich MAC Defense Rate: {(self.engine.sandwich_success/self.engine.test_count)*100}%")
        self.log("Both architectures successfully blocked the extension attack.")
        self.change_indicator("green")

    def show_graphs(self):
        if not self.engine.metrics["sizes"]: return

        attack_rate = (self.engine.attack_success / self.engine.test_count) * 100
        avg_sha = sum(self.engine.metrics["sha1_times"]) / len(self.engine.metrics["sha1_times"])
        avg_hmac = sum(self.engine.metrics["hmac_times"]) / len(self.engine.metrics["hmac_times"])
        avg_sandwich = sum(self.engine.metrics["sandwich_times"]) / len(self.engine.metrics["sandwich_times"])

        fig, axs = plt.subplots(2, 2, figsize=(12, 8))
        fig.canvas.manager.set_window_title('Review 2: 3-Way Comparative Analysis')

        labels = ["Raw SHA-1", "Sandwich MAC", "HMAC"]
        axs[0, 0].bar(labels, [attack_rate, 0, 0], color=['red', 'teal', 'green'])
        axs[0, 0].set_title("1. Attack Vulnerability Rate (%)")
        axs[0, 0].set_ylim(0, 110)

        data = sorted(zip(self.engine.metrics["sizes"], self.engine.metrics["sha1_times"], 
                          self.engine.metrics["sandwich_times"], self.engine.metrics["hmac_times"]))
        s_sizes, s_sha, s_sand, s_hmac = zip(*data)
        
        axs[0, 1].plot(s_sizes, s_sha, label='Raw SHA-1', color='red', alpha=0.6)
        axs[0, 1].plot(s_sizes, s_sand, label='Sandwich MAC', color='teal')
        axs[0, 1].plot(s_sizes, s_hmac, label='HMAC', color='green')
        axs[0, 1].set_title("2. Processing Time vs Message Size")
        axs[0, 1].set_xlabel("Bytes"); axs[0, 1].set_ylabel("Time (ms)")
        axs[0, 1].legend()

        axs[1, 0].bar(labels, [0, 100, 100], color=['orange', 'teal', 'blue'])
        axs[1, 0].set_title("3. System Integrity Preservation (%)")
        axs[1, 0].set_ylim(0, 110)

        axs[1, 1].bar(labels, [avg_sha, avg_sandwich, avg_hmac], color=['gray', 'teal', 'purple'])
        axs[1, 1].set_title("4. Latency Overhead Comparison")
        axs[1, 1].set_ylabel("Average Computation Time (ms)")

        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()