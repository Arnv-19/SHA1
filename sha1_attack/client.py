import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import binascii
from sha1 import SHA1, parse_mac, generate_padding

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-1 Length Extension Client")
        self.root.geometry("800x650")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab1, text="Normal Client Mode")
        self.notebook.add(self.tab2, text="Attacker Mode")
        self.notebook.add(self.tab3, text="SHA Internals")
        
        self._setup_tab1()
        self._setup_tab2()
        self._setup_tab3()
        
    def _send_request(self, msg_hex, mac):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', 5000))
            payload = json.dumps({"message": msg_hex, "mac": mac})
            s.sendall(payload.encode('utf-8'))
            
            data = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                
            s.close()
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            return None

    def _setup_tab1(self):
        frm = ttk.Frame(self.tab1, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frm, text="Message to Sign:").pack(anchor=tk.W)
        self.t1_msg = tk.StringVar(value="Hello Server!")
        ttk.Entry(frm, textvariable=self.t1_msg, width=50).pack(anchor=tk.W, pady=5)
        
        ttk.Button(frm, text="Send to Server (Generate MAC)", command=self.do_normal_request).pack(anchor=tk.W, pady=10)
        
        ttk.Label(frm, text="Server Response Details:").pack(anchor=tk.W)
        self.t1_out = scrolledtext.ScrolledText(frm, width=80, height=20, font=("Consolas", 10))
        self.t1_out.pack(fill=tk.BOTH, expand=True)

    def do_normal_request(self):
        msg = self.t1_msg.get().encode('utf-8')
        resp = self._send_request(msg.hex(), "")
        if not resp: return
        
        self.t1_out.delete(1.0, tk.END)
        self.t1_out.insert(tk.END, f"Returned MAC: {resp.get('mac')}\n")
        self.t1_out.insert(tk.END, f"Message len (bits with secret): {resp.get('msg_bits')}\n")
        self.t1_out.insert(tk.END, f"Number of Blocks: {len(resp.get('history', []))}\n")
        self.t1_out.insert(tk.END, f"Padding added (hex): {resp.get('padding')}\n")
        
        self._log_internals("Server SHA #1 (Original MAC)", resp.get('history', []), resp.get('msg_bits', 0), resp.get('padding', ''))
        
        # Prepopulate attacker tab
        self.t2_orig_msg.set(self.t1_msg.get())
        self.t2_orig_mac.set(resp.get('mac'))

    def _setup_tab2(self):
        frm = ttk.Frame(self.tab2, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        
        grid = ttk.Frame(frm)
        grid.pack(fill=tk.X, pady=5)
        
        ttk.Label(grid, text="Original Message:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.t2_orig_msg = tk.StringVar()
        ttk.Entry(grid, textvariable=self.t2_orig_msg, width=60).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(grid, text="Original MAC (hex):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.t2_orig_mac = tk.StringVar()
        ttk.Entry(grid, textvariable=self.t2_orig_mac, width=60).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(grid, text="Extension String:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.t2_ext = tk.StringVar(value="...malicious payload...")
        ttk.Entry(grid, textvariable=self.t2_ext, width=60).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        length_frm = ttk.Frame(grid)
        length_frm.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text="Secret Length BruteForce:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(length_frm, text="From:").pack(side=tk.LEFT)
        self.t2_min = tk.IntVar(value=1)
        ttk.Spinbox(length_frm, from_=1, to=100, textvariable=self.t2_min, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Label(length_frm, text="To:").pack(side=tk.LEFT)
        self.t2_max = tk.IntVar(value=32)
        ttk.Spinbox(length_frm, from_=1, to=100, textvariable=self.t2_max, width=5).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(frm, text="Perform Length Extension Attack", command=self.do_attack).pack(anchor=tk.W, pady=10)
        
        self.t2_out = scrolledtext.ScrolledText(frm, width=80, height=20, font=("Consolas", 10), bg="#2e0000", fg="#ffdddd")
        self.t2_out.pack(fill=tk.BOTH, expand=True)

    def do_attack(self):
        orig_msg = self.t2_orig_msg.get().encode('utf-8')
        orig_mac = self.t2_orig_mac.get()
        ext = self.t2_ext.get().encode('utf-8')
        min_l = self.t2_min.get()
        max_l = self.t2_max.get()
        
        if len(orig_mac) != 40:
            messagebox.showerror("Error", "Original MAC must be exactly 40 hex chars")
            return
            
        self.t2_out.delete(1.0, tk.END)
        self.t2_out.insert(tk.END, "[*] Starting Attack Brute-Force...\n")
        
        for l in range(min_l, max_l + 1):
            total_orig_len = l + len(orig_msg)
            padding = generate_padding(total_orig_len)
            
            forged_msg = orig_msg + padding + ext
            
            # Attacker sets up state manually
            h0, h1, h2, h3, h4 = parse_mac(orig_mac)
            
            state_msg_len = total_orig_len + len(padding)
            
            attacker_sha = SHA1(h0, h1, h2, h3, h4, message_byte_length=state_msg_len)
            attacker_sha.update(ext)
            forged_mac = attacker_sha.hexdigest()
            
            resp = self._send_request(forged_msg.hex(), forged_mac)
            if not resp:
                continue
                
            status = resp.get('status')
            
            self.t2_out.insert(tk.END, f"Guess Length: {l:<3} | Forged MAC: {forged_mac} | Resp: {status}\n")
            self.t2_out.see(tk.END)
            self.root.update()
            
            if status == "ACCEPTED":
                self.t2_out.insert(tk.END, "\n[SUCCESS] Attack completed!\n")
                self.t2_out.insert(tk.END, f"Correct Secret Length: {l}\n")
                self.t2_out.insert(tk.END, f"Reconstructed Padding (hex): {padding.hex()}\n")
                self.t2_out.insert(tk.END, f"Total Processed Byte Length: {state_msg_len + len(ext)}\n")
                self.t2_out.insert(tk.END, f"Final Forged Message (hex): {forged_msg.hex()}\n")
                ascii_forged = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in forged_msg)
                self.t2_out.insert(tk.END, f"Final Forged Message (ASCII): {ascii_forged}\n")
                self.t2_out.insert(tk.END, f"Final Forged MAC: {forged_mac}\n")
                
                # Log to Tab 3
                overall_len_bits = (state_msg_len + len(ext)) * 8
                attacker_pad = generate_padding(state_msg_len + len(ext))
                
                self._log_internals("Attacker SHA #2 (Forged Continuation)", attacker_sha.history, overall_len_bits, attacker_pad.hex())
                self._log_internals("Server SHA #3 (Verification)", resp.get('history', []), resp.get('msg_bits', 0), resp.get('padding', ''))
                break

    def _setup_tab3(self):
        frm = ttk.Frame(self.tab3, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(frm, text="Clear SHA Internals", command=lambda: self.t3_out.delete(1.0, tk.END)).pack(anchor=tk.W, pady=5)
        
        self.t3_out = scrolledtext.ScrolledText(frm, width=80, height=30, font=("Consolas", 10), bg="#1e1e3e", fg="#d4d4ff")
        self.t3_out.pack(fill=tk.BOTH, expand=True)

    def _log_internals(self, title, history, length_bits, padding_hex):
        self.t3_out.insert(tk.END, f"=== {title} ===\n")
        self.t3_out.insert(tk.END, f"Input Length (bits): {length_bits}\n")
        self.t3_out.insert(tk.END, f"Padding (hex): {padding_hex}\n")
        self.t3_out.insert(tk.END, f"Number of Blocks: {len(history)}\n\n")
        
        for i, blk in enumerate(history):
            self.t3_out.insert(tk.END, f"  [Block {i+1}]\n")
            self.t3_out.insert(tk.END, f"    Content (hex): {blk['chunk']}\n")
            self.t3_out.insert(tk.END, f"    Initial: h0={blk['initial_h'][0]:08x} h1={blk['initial_h'][1]:08x} h2={blk['initial_h'][2]:08x} h3={blk['initial_h'][3]:08x} h4={blk['initial_h'][4]:08x}\n")
            self.t3_out.insert(tk.END, f"    Final:   h0={blk['final_h'][0]:08x} h1={blk['final_h'][1]:08x} h2={blk['final_h'][2]:08x} h3={blk['final_h'][3]:08x} h4={blk['final_h'][4]:08x}\n\n")
            
        self.t3_out.insert(tk.END, "-"*60 + "\n\n")
        self.t3_out.see(tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
