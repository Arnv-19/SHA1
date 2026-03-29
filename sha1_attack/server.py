import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import os
from sha1 import SHA1, generate_padding, compute_hmac_sha1

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-1 Length Extension Attack Server")
        self.root.geometry("800x600")
        
        # Secret Key Length Setting
        self.secret_len_var = tk.IntVar(value=10)
        self.secret = os.urandom(self.secret_len_var.get())
        
        self._setup_gui()
        
        # TCP Server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', 5000))
        self.server_socket.listen(5)
        
        self.running = True
        self.server_thread = threading.Thread(target=self._accept_clients, daemon=True)
        self.server_thread.start()

    def _generate_secret(self, *args):
        try:
            length = self.secret_len_var.get()
            if 1 <= length <= 32:
                self.secret = os.urandom(length)
                self.log(f"[*] Generated new secret of length {length} bytes.\n")
        except:
            pass

    def _setup_gui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        
        ctrl_frm = ttk.Frame(frm)
        ctrl_frm.pack(fill=tk.X, pady=5)
        
        ttk.Label(ctrl_frm, text="Secret Length (bytes):").pack(side=tk.LEFT)
        spin = ttk.Spinbox(ctrl_frm, from_=1, to=32, textvariable=self.secret_len_var, width=5)
        spin.pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frm, text="Generate New Secret", command=self._generate_secret).pack(side=tk.LEFT, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(frm, width=80, height=30, font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log("[*] Server started. Listening on localhost:5000\n")

    def log(self, msg):
        self.root.after(0, self._append_log, msg)

    def _append_log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _accept_clients(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
            except:
                break

    def _handle_client(self, client, addr):
        try:
            data = b''
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'}' in chunk:
                    break
            
            if not data:
                return
                
            req = json.loads(data.decode('utf-8'))
            msg_hex = req.get('message', '')
            recv_mac = req.get('mac', '')
            use_hmac = req.get('use_hmac', False)
            
            try:
                msg_bytes = bytes.fromhex(msg_hex)
            except ValueError:
                msg_bytes = msg_hex.encode('utf-8')
                
            mac_mode = "HMAC-SHA1" if use_hmac else "SHA1-MAC"
            self.log(f"--- NEW REQUEST FROM {addr} [{mac_mode}] ---")
            self.log(f"Message (hex): {msg_bytes.hex()}")
            ascii_msg = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in msg_bytes)
            self.log(f"Message (ASCII): {ascii_msg}")
            
            if use_hmac:
                computed_mac = compute_hmac_sha1(self.secret, msg_bytes)
                self.log(f"Computed HMAC-SHA1: {computed_mac}")
                sha_history = []
                padding_hex = ""
                msg_bits = len(msg_bytes) * 8
            else:
                payload = self.secret + msg_bytes
                sha = SHA1()
                sha.update(payload)
                computed_mac = sha.hexdigest()
                sha_history = sha.history
                padding = generate_padding(len(payload))
                padding_hex = padding.hex()
                msg_bits = len(payload) * 8
                self.log(f"Message length in bits (including secret): {msg_bits}")
                self.log(f"Number of 512-bit blocks: {len(sha.history)}")
                self.log(f"Padding added (hex): {padding_hex}")
                for i, blk in enumerate(sha.history):
                    self.log(f"  Block {i} Content (hex): {blk['chunk']}")
                    self.log(f"    Initial h0-h4: {['%08x' % x for x in blk['initial_h']]}")
                    self.log(f"    Final h0-h4:   {['%08x' % x for x in blk['final_h']]}")
                self.log(f"Computed MAC: {computed_mac}")
            
            if recv_mac == "":
                self.log(f"Action: MAC GENERATION [{mac_mode}]")
                status = "GENERATED"
            else:
                self.log(f"Received MAC: {recv_mac}")
                status = "ACCEPTED" if computed_mac.lower() == recv_mac.lower() else "REJECTED"
                self.log(f"Action: VERIFICATION -> {status}")
            
            self.log("----------------------------------\n")
            
            res = json.dumps({
                "status": status,
                "mac": computed_mac,
                "mac_mode": mac_mode,
                "history": sha_history,
                "padding": padding_hex,
                "msg_bits": msg_bits
            })
            client.sendall(res.encode('utf-8'))
        except Exception as e:
            self.log(f"Error handling client: {e}")
        finally:
            client.close()

if __name__ == '__main__':
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
