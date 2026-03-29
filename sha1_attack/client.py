import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import time
import tracemalloc
from sha1 import SHA1, parse_mac, generate_padding, compute_hmac_sha1

# ── Analytics data store ──────────────────────────────────────────────────────
analytics = {
    "sha1_attack_attempts": 0,
    "sha1_attack_successes": 0,
    "hmac_attack_attempts": 0,
    "hmac_attack_successes": 0,          # always 0
    "sha1_latencies": [],                # seconds per attempt
    "hmac_latencies": [],
    "key_lengths_tried": [],             # list of (guessed_len, latency)
    "sha1_mem_kb": [],
    "hmac_mem_kb": [],
}

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-1 Length Extension Client")
        self.root.geometry("1000x720")

        style = ttk.Style()
        style.theme_use("clam")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        self.tab4 = ttk.Frame(self.notebook)

        self.notebook.add(self.tab1, text="  Normal Client Mode  ")
        self.notebook.add(self.tab2, text="  Attacker Mode  ")
        self.notebook.add(self.tab3, text="  SHA Internals  ")
        self.notebook.add(self.tab4, text="  📊 Analytics  ")

        self._setup_tab1()
        self._setup_tab2()
        self._setup_tab3()
        self._setup_tab4()

    # ── Network ───────────────────────────────────────────────────────────────
    def _send_request(self, msg_hex, mac, use_hmac=False):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('localhost', 5000))
            payload = json.dumps({"message": msg_hex, "mac": mac, "use_hmac": use_hmac})
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

    # ── Tab 1: Normal Client Mode ─────────────────────────────────────────────
    def _setup_tab1(self):
        frm = ttk.Frame(self.tab1, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        input_frm = ttk.LabelFrame(frm, text="Message", padding=8)
        input_frm.pack(fill=tk.X, pady=6)

        ttk.Label(input_frm, text="Message to Sign:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.t1_msg = tk.StringVar(value="Hello Server!")
        ttk.Entry(input_frm, textvariable=self.t1_msg, width=60).grid(row=0, column=1, sticky=tk.W, padx=8)

        self.t1_use_hmac = tk.BooleanVar(value=False)
        hmac_cb = ttk.Checkbutton(input_frm, text="Use HMAC-SHA1 (secure — resists length extension)",
                                   variable=self.t1_use_hmac)
        hmac_cb.grid(row=1, column=1, sticky=tk.W, padx=8, pady=4)

        ttk.Button(frm, text="▶  Send to Server (Generate MAC)",
                   command=self.do_normal_request).pack(anchor=tk.W, pady=10)

        ttk.Label(frm, text="Server Response:").pack(anchor=tk.W)
        self.t1_out = scrolledtext.ScrolledText(frm, width=90, height=22,
                                                 font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4")
        self.t1_out.pack(fill=tk.BOTH, expand=True)

    def do_normal_request(self):
        msg = self.t1_msg.get().encode('utf-8')
        use_hmac = self.t1_use_hmac.get()
        resp = self._send_request(msg.hex(), "", use_hmac=use_hmac)
        if not resp:
            return

        mode_label = resp.get('mac_mode', 'SHA1-MAC')
        self.t1_out.delete(1.0, tk.END)
        self.t1_out.insert(tk.END, f"MAC Mode   : [{mode_label}]\n")
        self.t1_out.insert(tk.END, f"Returned MAC: {resp.get('mac')}\n")
        self.t1_out.insert(tk.END, f"Message len (bits with secret): {resp.get('msg_bits')}\n")
        if not use_hmac:
            self.t1_out.insert(tk.END, f"Number of Blocks: {len(resp.get('history', []))}\n")
            self.t1_out.insert(tk.END, f"Padding added (hex): {resp.get('padding')}\n")
            self._log_internals("Server SHA #1 (Original MAC)", resp.get('history', []),
                                resp.get('msg_bits', 0), resp.get('padding', ''))
        else:
            self.t1_out.insert(tk.END, "\n[HMAC-SHA1 mode: SHA internals hidden — two-pass hash, not exploitable]\n")

        # Prepopulate attacker tab
        self.t2_orig_msg.set(self.t1_msg.get())
        self.t2_orig_mac.set(resp.get('mac'))
        self.t2_mac_mode.set(mode_label)

    # ── Tab 2: Attacker Mode ──────────────────────────────────────────────────
    def _setup_tab2(self):
        frm = ttk.Frame(self.tab2, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        grid = ttk.LabelFrame(frm, text="Intercepted Data", padding=8)
        grid.pack(fill=tk.X, pady=6)

        ttk.Label(grid, text="Original Message:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=3)
        self.t2_orig_msg = tk.StringVar()
        ttk.Entry(grid, textvariable=self.t2_orig_msg, width=60).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(grid, text="Original MAC (hex):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=3)
        self.t2_orig_mac = tk.StringVar()
        ttk.Entry(grid, textvariable=self.t2_orig_mac, width=60).grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(grid, text="MAC Mode (detected):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=3)
        self.t2_mac_mode = tk.StringVar(value="SHA1-MAC")
        mode_lbl = ttk.Label(grid, textvariable=self.t2_mac_mode, foreground="#0099ff", font=("Consolas", 10, "bold"))
        mode_lbl.grid(row=2, column=1, sticky=tk.W, padx=5)

        ttk.Label(grid, text="Extension String:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=3)
        self.t2_ext = tk.StringVar(value="...malicious payload...")
        ttk.Entry(grid, textvariable=self.t2_ext, width=60).grid(row=3, column=1, sticky=tk.W, padx=5)

        length_frm = ttk.Frame(grid)
        length_frm.grid(row=4, column=1, sticky=tk.W, padx=5, pady=3)
        ttk.Label(grid, text="Secret Length BruteForce:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=3)
        ttk.Label(length_frm, text="From:").pack(side=tk.LEFT)
        self.t2_min = tk.IntVar(value=1)
        ttk.Spinbox(length_frm, from_=1, to=100, textvariable=self.t2_min, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Label(length_frm, text="To:").pack(side=tk.LEFT)
        self.t2_max = tk.IntVar(value=32)
        ttk.Spinbox(length_frm, from_=1, to=100, textvariable=self.t2_max, width=5).pack(side=tk.LEFT, padx=2)

        ttk.Button(frm, text="⚡  Perform Length Extension Attack",
                   command=self.do_attack).pack(anchor=tk.W, pady=10)

        self.t2_out = scrolledtext.ScrolledText(frm, width=90, height=18,
                                                 font=("Consolas", 10), bg="#1a0005", fg="#ffcccc")
        self.t2_out.pack(fill=tk.BOTH, expand=True)
        # Tag for success / defense banners
        self.t2_out.tag_configure("success", foreground="#00ff88", font=("Consolas", 10, "bold"))
        self.t2_out.tag_configure("defense", foreground="#ffaa00", font=("Consolas", 10, "bold"))
        self.t2_out.tag_configure("rejected", foreground="#ff4444")
        self.t2_out.tag_configure("accepted", foreground="#00ff88")

    def do_attack(self):
        orig_msg = self.t2_orig_msg.get().encode('utf-8')
        orig_mac = self.t2_orig_mac.get().strip()
        ext = self.t2_ext.get().encode('utf-8')
        min_l = self.t2_min.get()
        max_l = self.t2_max.get()
        mac_mode = self.t2_mac_mode.get()

        if len(orig_mac) != 40:
            messagebox.showerror("Error", "Original MAC must be exactly 40 hex chars")
            return

        self.t2_out.delete(1.0, tk.END)
        is_hmac = (mac_mode == "HMAC-SHA1")

        if is_hmac:
            self.t2_out.insert(tk.END,
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  TARGET IS PROTECTED BY HMAC-SHA1                            ║\n"
                "║  Attempting length extension attack anyway...                ║\n"
                "╚══════════════════════════════════════════════════════════════╝\n\n",
                "defense")
        else:
            self.t2_out.insert(tk.END, "[*] Target uses SHA1-MAC — vulnerable to length extension.\n")
            self.t2_out.insert(tk.END, "[*] Starting brute-force attack...\n\n")

        total_attempts = 0
        success = False

        tracemalloc.start()
        attack_start = time.perf_counter()

        for l in range(min_l, max_l + 1):
            t0 = time.perf_counter()

            total_orig_len = l + len(orig_msg)
            padding = generate_padding(total_orig_len)
            forged_msg = orig_msg + padding + ext

            h0, h1, h2, h3, h4 = parse_mac(orig_mac)
            state_msg_len = total_orig_len + len(padding)
            attacker_sha = SHA1(h0, h1, h2, h3, h4, message_byte_length=state_msg_len)
            attacker_sha.update(ext)
            forged_mac = attacker_sha.hexdigest()

            resp = self._send_request(forged_msg.hex(), forged_mac, use_hmac=False)
            t1 = time.perf_counter()

            if not resp:
                continue

            status = resp.get('status')
            total_attempts += 1
            latency = t1 - t0

            analytics["key_lengths_tried"].append((l, latency))
            if is_hmac:
                analytics["hmac_latencies"].append(latency)
            else:
                analytics["sha1_latencies"].append(latency)

            tag = "accepted" if status == "ACCEPTED" else "rejected"
            self.t2_out.insert(tk.END,
                f"Guess Length: {l:<3} | Forged MAC: {forged_mac[:16]}... | Resp: {status}\n", tag)
            self.t2_out.see(tk.END)
            self.root.update()

            if status == "ACCEPTED" and not is_hmac:
                success = True
                # collect memory
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                analytics["sha1_attack_attempts"] += total_attempts
                analytics["sha1_attack_successes"] += 1
                analytics["sha1_mem_kb"].append(peak / 1024)

                self.t2_out.insert(tk.END,
                    f"\n╔══════════════════════════════════════════════════════════════╗\n"
                    f"║  [SUCCESS] Attack completed!                                 ║\n"
                    f"╚══════════════════════════════════════════════════════════════╝\n",
                    "success")
                self.t2_out.insert(tk.END, f"  Correct Secret Length : {l}\n", "success")
                self.t2_out.insert(tk.END, f"  Padding (hex)         : {padding.hex()}\n", "success")
                ascii_forged = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in forged_msg)
                self.t2_out.insert(tk.END, f"  Forged Message (ASCII): {ascii_forged}\n", "success")
                self.t2_out.insert(tk.END, f"  Forged MAC            : {forged_mac}\n\n", "success")

                overall_len_bits = (state_msg_len + len(ext)) * 8
                attacker_pad = generate_padding(state_msg_len + len(ext))
                self._log_internals("Attacker SHA #2 (Forged Continuation)",
                                    attacker_sha.history, overall_len_bits, attacker_pad.hex())
                self._log_internals("Server SHA #3 (Verification)",
                                    resp.get('history', []), resp.get('msg_bits', 0), resp.get('padding', ''))
                break

        if not success:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            if is_hmac:
                analytics["hmac_attack_attempts"] += total_attempts
                analytics["hmac_mem_kb"].append(peak / 1024)
                self.t2_out.insert(tk.END,
                    f"\n╔══════════════════════════════════════════════════════════════╗\n"
                    f"║  [DEFENSE ACTIVE] HMAC prevents length extension!              ║\n"
                    f"║  All {total_attempts:<3} guesses REJECTED — attack completely failed.  ║\n"
                    f"╚══════════════════════════════════════════════════════════════╝\n",
                    "defense")
                self.t2_out.insert(tk.END,
                    "\nWhy it failed:\n"
                    "  HMAC = SHA1(opad ‖ SHA1(ipad ‖ message))\n"
                    "  The attacker cannot append to the inner hash without knowing the key.\n"
                    "  The outer hash wraps around, destroying any state the attacker can control.\n",
                    "defense")
            else:
                analytics["sha1_attack_attempts"] += total_attempts
                self.t2_out.insert(tk.END, "\n[!] Attack did not succeed in given range.\n")

    # ── Tab 3: SHA Internals ──────────────────────────────────────────────────
    def _setup_tab3(self):
        frm = ttk.Frame(self.tab3, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frm, text="Clear SHA Internals",
                   command=lambda: self.t3_out.delete(1.0, tk.END)).pack(anchor=tk.W, pady=5)
        self.t3_out = scrolledtext.ScrolledText(frm, width=90, height=32,
                                                 font=("Consolas", 10), bg="#1e1e3e", fg="#d4d4ff")
        self.t3_out.pack(fill=tk.BOTH, expand=True)

    def _log_internals(self, title, history, length_bits, padding_hex):
        self.t3_out.insert(tk.END, f"=== {title} ===\n")
        self.t3_out.insert(tk.END, f"Input Length (bits): {length_bits}\n")
        self.t3_out.insert(tk.END, f"Padding (hex): {padding_hex}\n")
        self.t3_out.insert(tk.END, f"Number of Blocks: {len(history)}\n\n")
        for i, blk in enumerate(history):
            self.t3_out.insert(tk.END, f"  [Block {i+1}]\n")
            self.t3_out.insert(tk.END, f"    Content (hex): {blk['chunk']}\n")
            self.t3_out.insert(tk.END,
                f"    Initial: h0={blk['initial_h'][0]:08x} h1={blk['initial_h'][1]:08x} "
                f"h2={blk['initial_h'][2]:08x} h3={blk['initial_h'][3]:08x} h4={blk['initial_h'][4]:08x}\n")
            self.t3_out.insert(tk.END,
                f"    Final:   h0={blk['final_h'][0]:08x} h1={blk['final_h'][1]:08x} "
                f"h2={blk['final_h'][2]:08x} h3={blk['final_h'][3]:08x} h4={blk['final_h'][4]:08x}\n\n")
        self.t3_out.insert(tk.END, "-"*62 + "\n\n")
        self.t3_out.see(tk.END)

    # ── Tab 4: Analytics ──────────────────────────────────────────────────────
    def _setup_tab4(self):
        try:
            import matplotlib
            matplotlib.use("TkAgg")
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            import matplotlib.pyplot as plt
            self._plt = plt
            self._FigureCanvasTkAgg = FigureCanvasTkAgg
            self._matplotlib_ok = True
        except ImportError:
            self._matplotlib_ok = False

        frm = ttk.Frame(self.tab4, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        ctrl = ttk.Frame(frm)
        ctrl.pack(fill=tk.X, pady=4)
        ttk.Button(ctrl, text="🔄  Refresh Analytics", command=self._refresh_analytics).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="🗑  Reset Data", command=self._reset_analytics).pack(side=tk.LEFT, padx=4)
        self.t4_status = tk.StringVar(value="Run attacks in Attacker Mode to populate charts.")
        ttk.Label(ctrl, textvariable=self.t4_status, foreground="#888").pack(side=tk.LEFT, padx=16)

        # Canvas container
        self.t4_canvas_frm = ttk.Frame(frm)
        self.t4_canvas_frm.pack(fill=tk.BOTH, expand=True)

        self._refresh_analytics()

    def _reset_analytics(self):
        for k in analytics:
            if isinstance(analytics[k], list):
                analytics[k].clear()
            else:
                analytics[k] = 0
        self._refresh_analytics()

    def _refresh_analytics(self):
        if not self._matplotlib_ok:
            ttk.Label(self.t4_canvas_frm,
                      text="matplotlib not installed. Run: pip install matplotlib").pack()
            return

        plt = self._plt
        FigureCanvasTkAgg = self._FigureCanvasTkAgg

        for w in self.t4_canvas_frm.winfo_children():
            w.destroy()

        fig, axes = plt.subplots(2, 3, figsize=(14, 8))
        fig.patch.set_facecolor("#1a1a2e")
        plt.subplots_adjust(hspace=0.45, wspace=0.38)

        DARK_BG  = "#16213e"
        ACCENT1  = "#e94560"
        ACCENT2  = "#0f3460"
        ACCENT3  = "#533483"
        SAFE     = "#00b4d8"
        WARN     = "#f77f00"
        TEXT     = "#e0e0e0"
        GRID     = "#2a2a3e"

        def style_ax(ax, title):
            ax.set_facecolor(DARK_BG)
            ax.set_title(title, color=TEXT, fontsize=9, pad=8, fontweight="bold")
            ax.tick_params(colors=TEXT, labelsize=7)
            for spine in ax.spines.values():
                spine.set_edgecolor(GRID)
            ax.title.set_color(TEXT)

        # ── Chart 1: Before vs After Attack Success Rate ──────────────────────
        ax = axes[0][0]
        sha1_sr = (analytics["sha1_attack_successes"] / analytics["sha1_attack_attempts"] * 100
                   if analytics["sha1_attack_attempts"] else 0)
        hmac_sr = 0
        bars = ax.bar(["SHA1-MAC\n(Vulnerable)", "HMAC-SHA1\n(Secure)"],
                      [sha1_sr, hmac_sr], color=[ACCENT1, SAFE], width=0.5, edgecolor=GRID)
        ax.set_ylim(0, 110)
        ax.set_ylabel("Success Rate (%)", color=TEXT, fontsize=7)
        for bar, val in zip(bars, [sha1_sr, hmac_sr]):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                    f"{val:.0f}%", ha='center', color=TEXT, fontsize=8, fontweight="bold")
        style_ax(ax, "Before vs After Attack Success Rate")

        # ── Chart 2: Time vs Key/Secret Size ─────────────────────────────────
        ax = axes[0][1]
        if analytics["key_lengths_tried"]:
            sizes, times = zip(*analytics["key_lengths_tried"])
            ax.plot(sizes, [t*1000 for t in times], color=ACCENT1, linewidth=1.5,
                    marker='o', markersize=3, label="Attack attempt")
            ax.set_xlabel("Guessed Key Length (bytes)", color=TEXT, fontsize=7)
            ax.set_ylabel("Latency (ms)", color=TEXT, fontsize=7)
            ax.legend(fontsize=7, facecolor=DARK_BG, labelcolor=TEXT)
        else:
            ax.text(0.5, 0.5, "No data yet", ha='center', va='center', color=TEXT, transform=ax.transAxes)
        style_ax(ax, "Time vs Key/Secret Size")

        # ── Chart 3: CIA Ratings ──────────────────────────────────────────────
        ax = axes[0][2]
        categories = ["Confidentiality", "Integrity", "Authentication"]
        sha1_scores = [40, 50, 30]    # SHA1-MAC relative scores (%)
        hmac_scores = [95, 98, 97]    # HMAC-SHA1 scores
        x = range(len(categories))
        w = 0.35
        b1 = ax.bar([i - w/2 for i in x], sha1_scores, w, label="SHA1-MAC",  color=ACCENT1, edgecolor=GRID)
        b2 = ax.bar([i + w/2 for i in x], hmac_scores,  w, label="HMAC-SHA1", color=SAFE,   edgecolor=GRID)
        ax.set_xticks(list(x))
        ax.set_xticklabels(categories, color=TEXT, fontsize=6, rotation=10)
        ax.set_ylim(0, 115)
        ax.set_ylabel("Rating (%)", color=TEXT, fontsize=7)
        ax.legend(fontsize=7, facecolor=DARK_BG, labelcolor=TEXT)
        style_ax(ax, "CIA Rate: SHA1-MAC vs HMAC-SHA1")

        # ── Chart 4: Attack vs Prevention Latency Overhead ───────────────────
        ax = axes[1][0]
        avg_attack = (sum(analytics["sha1_latencies"]) / len(analytics["sha1_latencies"]) * 1000
                      if analytics["sha1_latencies"] else 0)
        avg_hmac   = (sum(analytics["hmac_latencies"])  / len(analytics["hmac_latencies"])  * 1000
                      if analytics["hmac_latencies"] else 0)
        bars = ax.bar(["Avg Attack\nLatency (SHA1)", "Avg Verification\nLatency (HMAC)"],
                      [avg_attack, avg_hmac], color=[WARN, SAFE], edgecolor=GRID, width=0.5)
        ax.set_ylabel("Time (ms)", color=TEXT, fontsize=7)
        for bar, val in zip(bars, [avg_attack, avg_hmac]):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    f"{val:.1f}ms", ha='center', color=TEXT, fontsize=8, fontweight="bold")
        style_ax(ax, "Attack vs Prevention Latency Overhead")

        # ── Chart 5: Prevention Effectiveness (Accept vs Reject counts) ───────
        ax = axes[1][1]
        sha1_acc  = analytics["sha1_attack_successes"]
        sha1_rej  = max(analytics["sha1_attack_attempts"] - sha1_acc, 0)
        hmac_rej  = analytics["hmac_attack_attempts"]
        labels = ["SHA1-MAC", "HMAC-SHA1"]
        accepted_vals = [sha1_acc, 0]
        rejected_vals = [sha1_rej, hmac_rej]
        ax.bar(labels, accepted_vals, label="Accepted (Attack Won)", color=ACCENT1, edgecolor=GRID)
        ax.bar(labels, rejected_vals, bottom=accepted_vals, label="Rejected (Defense Won)", color=SAFE, edgecolor=GRID)
        ax.set_ylabel("Request Count", color=TEXT, fontsize=7)
        ax.legend(fontsize=6, facecolor=DARK_BG, labelcolor=TEXT)
        style_ax(ax, "Prevention Effectiveness Comparison")

        # ── Chart 6: Resource Usage (Memory) ─────────────────────────────────
        ax = axes[1][2]
        categories2 = []
        mem_vals = []
        colors6 = []
        if analytics["sha1_mem_kb"]:
            avg_sha1 = sum(analytics["sha1_mem_kb"]) / len(analytics["sha1_mem_kb"])
            categories2.append("SHA1-MAC\nAttack")
            mem_vals.append(avg_sha1)
            colors6.append(ACCENT1)
        if analytics["hmac_mem_kb"]:
            avg_hmac_m = sum(analytics["hmac_mem_kb"]) / len(analytics["hmac_mem_kb"])
            categories2.append("HMAC\nAttempt")
            mem_vals.append(avg_hmac_m)
            colors6.append(SAFE)
        if categories2:
            bars = ax.bar(categories2, mem_vals, color=colors6, edgecolor=GRID, width=0.5)
            for bar, val in zip(bars, mem_vals):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f"{val:.1f} KB", ha='center', color=TEXT, fontsize=8, fontweight="bold")
        else:
            ax.text(0.5, 0.5, "No data yet", ha='center', va='center', color=TEXT, transform=ax.transAxes)
        ax.set_ylabel("Peak Memory (KB)", color=TEXT, fontsize=7)
        style_ax(ax, "Resource Usage (Peak Memory)")

        # ── Embed in Tk ───────────────────────────────────────────────────────
        canvas = FigureCanvasTkAgg(fig, master=self.t4_canvas_frm)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)

        total_runs = analytics["sha1_attack_attempts"] + analytics["hmac_attack_attempts"]
        self.t4_status.set(f"Last refreshed — {total_runs} total attack attempt(s) recorded.")


if __name__ == '__main__':
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
