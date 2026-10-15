"""Tkinter desktop app for the phishing email detector.

1. Start the API first (from the project root):   uvicorn api.main:app --reload
2. Then run:                                      python app/desktop_app.py
   (or just double-click run_demo.bat, which does both)

Uses only the Python standard library (tkinter, urllib, email), so no extra installs.
"""
import json
import threading
import tkinter as tk
import tkinter.font as tkfont
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from tkinter import filedialog, messagebox

DEFAULT_API = "http://127.0.0.1:8000"

SAMPLES = {
    "Phishing example": (
        "Your account has been suspended",
        "Dear valued customer,\n\nWe detected unusual sign-in activity on your account. To avoid permanent "
        "suspension you must verify your identity within 24 hours.\n\nClick here to confirm your details: "
        "http://secure-account-verify.com/login\n\nFailure to act will result in loss of access!!!\n\nSecurity Team",
    ),
    "Spam example": (
        "Cheap replica watches - 80% off today only",
        "Buy luxury replica watches at the lowest prices online! Rolex, Omega, Breitling. "
        "Free shipping worldwide. Order now at www.best-replicas.biz $$$",
    ),
    "Legitimate example": (
        "Re: ITRI625 project meeting",
        "Hi,\n\nCan we move Thursday's project meeting to 14:00? I've pushed the latest notebook changes to "
        "GitHub so you can pull before then. Let me know if the API runs on your side.\n\nThanks",
    ),
}

# ---- palette (one place to restyle the whole app) ----
C = {
    "bg": "#eef2f7",          # window background
    "card": "#ffffff",        # card background
    "border": "#d9e1ec",
    "header": "#0f1b2d",      # dark header bar
    "header_sub": "#93a4bd",
    "ink": "#1e293b",         # main text
    "muted": "#64748b",       # secondary text
    "accent": "#2563eb",      # primary button / focus
    "accent_hover": "#1d4ed8",
    "btn": "#e8edf5",
    "btn_hover": "#dbe3ef",
    "danger": "#dc2626", "danger_bg": "#fef2f2", "danger_soft": "#fecaca",
    "safe": "#16a34a", "safe_bg": "#f0fdf4", "safe_soft": "#bbf7d0",
    "warn": "#f59e0b",
}


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _HTMLText()
    p.feed(html)
    return " ".join(" ".join(p.parts).split())


def parse_eml(path):
    """Read a .eml file and return (subject, plain-text body)."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    subject = msg.get("subject", "") or ""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return subject, ""
    content = part.get_content()
    return subject, html_to_text(content) if part.get_content_type() == "text/html" else content


def _mix(c1, c2, t):
    """Blend two #rrggbb colours (t = 0 -> c1, t = 1 -> c2)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def round_rect(canvas, x1, y1, x2, y2, r, **kw):
    """Draw a rectangle with soft, rounded corners on a Canvas."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class FlatButton(tk.Canvas):
    """A soft, rounded button drawn on a Canvas, so it looks the same on Windows, macOS and Linux."""

    KINDS = {"primary": (C["accent"], C["accent_hover"], "#ffffff"),
             "secondary": (C["btn"], C["btn_hover"], C["ink"]),
             "ghost": (C["card"], C["btn"], C["muted"])}

    def __init__(self, parent, text, command, kind="secondary", font=None, radius=18, padx=18, pady=9,
                 colors=None):
        self.command, self.enabled, self.hover = command, True, False
        self.colors = colors or self.KINDS[kind]
        self.text, self.radius, self.padx, self.pady = text, radius, padx, pady
        self.font = tkfont.Font(font=font) if font else tkfont.nametofont("TkDefaultFont")
        w = self.font.measure(text) + 2 * padx
        h = self.font.metrics("linespace") + 2 * pady
        super().__init__(parent, width=w, height=h, bg=parent.cget("bg"), highlightthickness=0, bd=0,
                         cursor="hand2")
        self._draw()
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<Button-1>", lambda _e: self.enabled and self.command())

    def _draw(self):
        self.delete("all")
        w, h = int(self.cget("width")), int(self.cget("height"))
        bg = self.colors[1] if (self.hover and self.enabled) else self.colors[0]
        fg = self.colors[2] if self.enabled else C["muted"]
        round_rect(self, 1, 1, w - 1, h - 1, self.radius, fill=bg, outline=bg)
        self.create_text(w / 2, h / 2, text=self.text, fill=fg, font=self.font)

    def _set_hover(self, on):
        self.hover = on
        self._draw()

    def set_colors(self, colors):
        self.colors = colors
        self._draw()

    def set_enabled(self, on, text=None):
        self.enabled = on
        if text:
            self.text = text
            need = self.font.measure(text) + 2 * self.padx
            if need > int(self.cget("width")):
                self.configure(width=need)
        self.configure(cursor="hand2" if on else "watch")
        self._draw()


class PhishingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Email Detector | ITRI625")
        w, h = min(1240, self.winfo_screenwidth() - 40), min(800, self.winfo_screenheight() - 80)
        self.geometry(f"{w}x{h}")
        self.minsize(980, 620)
        self.configure(bg=C["bg"])
        self.api_url = tk.StringVar(value=DEFAULT_API)
        self.model_choice = tk.StringVar(value="bilstm")
        self.last_result = None
        self.history = []
        self._fonts()
        self._build_ui()
        self.after(200, self.check_health)

    # ---------------- fonts ----------------
    def _fonts(self):
        fams = set(tkfont.families(self))
        ui = next((f for f in ("Segoe UI", "SF Pro Text", "Helvetica Neue", "DejaVu Sans") if f in fams), "TkDefaultFont")
        mono = next((f for f in ("Cascadia Mono", "Consolas", "Menlo", "DejaVu Sans Mono") if f in fams), "TkFixedFont")
        self.f = {
            "title": (ui, 15, "bold"), "sub": (ui, 9), "h": (ui, 11, "bold"), "body": (ui, 10),
            "small": (ui, 9), "btn": (ui, 10, "bold"), "verdict": (ui, 24, "bold"), "big": (ui, 13, "bold"),
            "stat": (ui, 18, "bold"), "mono": (mono, 10), "icon": (ui, 28, "bold"),
        }

    # ---------------- layout ----------------
    def _card(self, parent, title=None, subtitle=None):
        outer = tk.Frame(parent, bg=C["border"])                      # 1px border
        inner = tk.Frame(outer, bg=C["card"], padx=18, pady=14)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            tk.Label(inner, text=title, font=self.f["h"], bg=C["card"], fg=C["ink"]).pack(anchor="w")
        if subtitle:
            tk.Label(inner, text=subtitle, font=self.f["small"], bg=C["card"], fg=C["muted"],
                     justify="left", wraplength=440).pack(anchor="w", pady=(2, 8))
        return outer, inner

    def _build_ui(self):
        # ---- header ----
        header = tk.Frame(self, bg=C["header"], padx=22, pady=12)
        header.pack(fill="x")
        logo = tk.Canvas(header, width=36, height=36, bg=C["header"], highlightthickness=0)
        logo.create_polygon(18, 3, 32, 9, 32, 19, 18, 33, 4, 19, 4, 9, fill=C["accent"], outline="")
        logo.create_text(18, 18, text="@", fill="#ffffff", font=self.f["big"])
        logo.pack(side="left", padx=(0, 12))
        titles = tk.Frame(header, bg=C["header"])
        titles.pack(side="left")
        tk.Label(titles, text="Phishing Email Detector", font=self.f["title"], bg=C["header"], fg="#ffffff").pack(anchor="w")
        tk.Label(titles, text="ITRI625  ·  BiLSTM deep learning model with explainable results",
                 font=self.f["sub"], bg=C["header"], fg=C["header_sub"]).pack(anchor="w")

        # model segmented control
        seg = tk.Frame(header, bg=C["header"])
        seg.pack(side="right")
        tk.Label(header, text="Model", font=self.f["small"], bg=C["header"], fg=C["header_sub"]).pack(side="right", padx=8)
        self.seg_btns = {}
        for key, label in (("bilstm", "BiLSTM"), ("baseline", "TF-IDF baseline")):
            b = FlatButton(seg, label, lambda k=key: self._set_model(k), font=self.f["btn"],
                           radius=22, padx=16, pady=6)
            b.pack(side="left", padx=2)
            self.seg_btns[key] = b
        self._set_model("bilstm")

        # ---- footer / status bar ----
        footer = tk.Frame(self, bg=C["card"], padx=22, pady=7, highlightthickness=1, highlightbackground=C["border"])
        footer.pack(fill="x", side="bottom")
        self.status_dot = tk.Canvas(footer, width=12, height=12, bg=C["card"], highlightthickness=0)
        self.status_dot.pack(side="left")
        self.dot = self.status_dot.create_oval(2, 2, 11, 11, fill=C["warn"], outline="")
        self.status = tk.Label(footer, text="Checking API...", font=self.f["small"], bg=C["card"], fg=C["muted"])
        self.status.pack(side="left", padx=(6, 0))
        FlatButton(footer, "Reconnect", self.check_health, "ghost", font=self.f["small"], pady=5, padx=12).pack(side="right")
        tk.Entry(footer, textvariable=self.api_url, width=28, font=self.f["small"], relief="flat",
                 bg=C["bg"], fg=C["ink"], highlightthickness=0).pack(side="right", padx=8, ipady=3)
        tk.Label(footer, text="API", font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(side="right")

        # ---- body: two columns ----
        body = tk.Frame(self, bg=C["bg"], padx=18, pady=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=5, uniform="cols")
        body.columnconfigure(1, weight=4, uniform="cols")
        body.rowconfigure(0, weight=1)

        # left column: the email
        lcard, left = self._card(body, "Email to analyse", "Paste an email, open a .eml file or load a sample.")
        lcard.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(left, text="SUBJECT", font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(anchor="w")
        sub_wrap = tk.Frame(left, bg=C["border"])
        sub_wrap.pack(fill="x", pady=(3, 12))
        self.subject = tk.Entry(sub_wrap, font=self.f["body"], relief="flat", bg="#f8fafc", fg=C["ink"],
                                insertbackground=C["ink"], highlightthickness=1, highlightcolor=C["accent"],
                                highlightbackground=C["border"])
        self.subject.pack(fill="x", ipady=7)
        # bottom row first so it never gets pushed off-screen by the text box
        tk.Label(left, text="Tip: Ctrl+Enter analyses. Highlighted words show what influenced the model.",
                 font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(side="bottom", anchor="w", pady=(10, 0))
        bar = tk.Frame(left, bg=C["card"])
        bar.pack(side="bottom", fill="x")
        self.analyse_btn = FlatButton(bar, "Analyse email   ⏎", self.analyse, "primary", font=self.f["btn"])
        self.analyse_btn.pack(side="left")
        FlatButton(bar, "Open .eml", self.load_eml, font=self.f["btn"]).pack(side="left", padx=8)
        self.sample_btn = FlatButton(bar, "Samples  ▾", self._sample_menu, font=self.f["btn"])
        self.sample_btn.pack(side="left")
        FlatButton(bar, "Clear", self.clear, "ghost", font=self.f["btn"]).pack(side="right")
        tk.Label(left, text="BODY", font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(anchor="w")
        txt_wrap = tk.Frame(left, bg=C["card"])
        txt_wrap.pack(fill="both", expand=True, pady=(3, 12))
        self.body = tk.Text(txt_wrap, wrap="word", font=self.f["mono"], relief="flat", bg="#f8fafc", fg=C["ink"],
                            insertbackground=C["ink"], undo=True, padx=12, pady=10, highlightthickness=1,
                            highlightcolor=C["accent"], highlightbackground=C["border"], spacing1=2, spacing3=2,
                            height=8)
        sb = tk.Scrollbar(txt_wrap, command=self.body.yview)
        self.body.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.body.pack(side="left", fill="both", expand=True)
        self.body.tag_configure("phish", background=C["danger_soft"], foreground="#7f1d1d")
        self.body.tag_configure("legit", background=C["safe_soft"], foreground="#14532d")
        self.bind("<Control-Return>", lambda _e: (self.analyse(), "break"))

        # right column: results
        right = tk.Frame(body, bg=C["bg"])
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        vcard, vin = self._card(right)
        vcard.pack(fill="x")
        self.verdict_box = tk.Frame(vin, bg=C["bg"], padx=16, pady=12)
        self.verdict_box.pack(fill="x")
        self.v_icon = tk.Label(self.verdict_box, text="?", font=self.f["icon"], width=2, bg=C["bg"], fg=C["muted"])
        self.v_icon.pack(side="left")
        vt = tk.Frame(self.verdict_box, bg=C["bg"])
        vt.pack(side="left", padx=10)
        self.v_title = tk.Label(vt, text="No email analysed yet", font=self.f["big"], bg=C["bg"], fg=C["ink"])
        self.v_title.pack(anchor="w")
        self.v_sub = tk.Label(vt, text="Results appear here", font=self.f["small"], bg=C["bg"], fg=C["muted"])
        self.v_sub.pack(anchor="w")
        self.v_pct = tk.Label(self.verdict_box, text="", font=self.f["verdict"], bg=C["bg"], fg=C["muted"])
        self.v_pct.pack(side="right")
        tk.Label(vin, text="PHISHING RISK", font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(anchor="w", pady=(14, 2))
        self.gauge = tk.Canvas(vin, height=46, bg=C["card"], highlightthickness=0)
        self.gauge.pack(fill="x")
        self.gauge.bind("<Configure>", lambda _e: self._draw_gauge())

        stats = tk.Frame(right, bg=C["bg"])
        stats.pack(fill="x", pady=12)
        self.stat_vals = {}
        for i, (key, label) in enumerate((("url_count", "Links"), ("word_count", "Words"), ("exclamation_marks", "'!' marks"))):
            sc, si = self._card(stats)
            sc.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            stats.columnconfigure(i, weight=1, uniform="stats")
            v = tk.Label(si, text="–", font=self.f["stat"], bg=C["card"], fg=C["ink"])
            v.pack(anchor="w")
            tk.Label(si, text=label, font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(anchor="w")
            self.stat_vals[key] = v

        hcard, hin = self._card(right, "Recent checks")
        hcard.pack(side="bottom", fill="x", pady=(12, 0))
        self.hist_frame = tk.Frame(hin, bg=C["card"])
        self.hist_frame.pack(fill="x")
        self._draw_history()

        wcard, win = self._card(right, "Why this verdict?",
                                "Words that pushed the model towards phishing (red) or legitimate (green). "
                                "Bar length = change in the model's log-odds when that word is removed.")
        wcard.pack(fill="both", expand=True)
        self.why = tk.Canvas(win, bg=C["card"], highlightthickness=0, height=120)
        self.why.pack(fill="both", expand=True)
        self.why.bind("<Configure>", lambda _e: self._draw_why())

    # ---------------- small UI helpers ----------------
    def _set_model(self, key):
        self.model_choice.set(key)
        for k, b in self.seg_btns.items():
            on = k == key
            b.set_colors((C["accent"], C["accent_hover"], "#ffffff") if on
                         else ("#1e2c42", "#2a3b56", C["header_sub"]))

    def _sample_menu(self):
        menu = tk.Menu(self, tearoff=False, font=self.f["body"])
        for name in SAMPLES:
            menu.add_command(label=name, command=lambda n=name: self.load_sample(n))
        x, y = self.sample_btn.winfo_rootx(), self.sample_btn.winfo_rooty() + self.sample_btn.winfo_height()
        menu.tk_popup(x, y)

    def _set_status(self, text, colour):
        self.status.configure(text=text)
        self.status_dot.itemconfigure(self.dot, fill=colour)

    def _draw_gauge(self):
        g = self.gauge
        g.delete("all")
        w = max(g.winfo_width(), 50)
        x0, x1, y0, y1 = 2, w - 2, 8, 22
        steps = 60
        for i in range(steps):                       # green -> amber -> red gradient bar
            t = i / (steps - 1)
            col = _mix(C["safe"], C["warn"], t * 2) if t < 0.5 else _mix(C["warn"], C["danger"], (t - 0.5) * 2)
            g.create_rectangle(x0 + (x1 - x0) * i / steps, y0, x0 + (x1 - x0) * (i + 1) / steps + 1, y1,
                               fill=col, outline="")
        r = self.last_result
        for frac, lab in ((0, "0%"), (0.5, "50%"), (1, "100%")):
            if r and frac == 0.5 and abs(r["threshold"] - 0.5) < 0.2:
                continue                              # the threshold label sits here instead
            g.create_text(x0 + (x1 - x0) * frac, 38, text=lab, font=self.f["small"], fill=C["muted"],
                          anchor={0: "w", 0.5: "center", 1: "e"}[frac])
        if r:
            tx = x0 + (x1 - x0) * r["threshold"]
            g.create_line(tx, y0 - 4, tx, y1 + 4, fill=C["ink"], dash=(2, 2))
            g.create_text(tx + 4, 38, text=f"threshold {r['threshold']:.2f}", font=self.f["small"],
                          fill=C["ink"], anchor="w")
            px = x0 + (x1 - x0) * r["probability"]
            g.create_polygon(px - 7, 1, px + 7, 1, px, y0 + 4, fill=C["ink"], outline="")
            g.create_line(px, y0, px, y1, fill="#ffffff", width=3)

    def _draw_why(self):
        cv = self.why
        cv.delete("all")
        w, h = max(cv.winfo_width(), 100), max(cv.winfo_height(), 60)
        toks = (self.last_result or {}).get("top_tokens") or []
        if not toks:
            cv.create_text(w / 2, h / 2, text="Analyse an email to see which words mattered.",
                           font=self.f["body"], fill=C["muted"])
            return
        toks = toks[:max(3, min(8, int(h // 22)))]     # only as many rows as fit legibly
        row = min(26, h / len(toks))
        label_w, pad = 140, 48                       # token names | value labels either side
        half = (w - label_w - 2 * pad) / 2
        mid = label_w + pad + half
        big = max(abs(t["weight"]) for t in toks) or 1
        cv.create_line(mid, 0, mid, row * len(toks), fill=C["border"])
        for i, t in enumerate(toks):
            y = i * row + row / 2
            wt = t["weight"]
            col = C["danger"] if wt > 0 else C["safe"]
            name = t["token"].replace("urltoken", "[link]").replace("numtoken", "[number]").replace("emailtoken", "[email]")
            name = name if len(name) <= 14 else name[:13] + "…"
            cv.create_text(label_w - 10, y, text=name, font=self.f["body"], fill=C["ink"], anchor="e")
            length = half * abs(wt) / big
            xa, xb = (mid, mid + length) if wt > 0 else (mid - length, mid)
            cv.create_rectangle(xa, y - row * 0.32, xb, y + row * 0.32, fill=col, outline="")
            cv.create_text(xb + 6 if wt > 0 else xa - 6, y, text=f"{wt:+.2f}", font=self.f["small"],
                           fill=C["muted"], anchor="w" if wt > 0 else "e")

    def _draw_history(self):
        for wdg in self.hist_frame.winfo_children():
            wdg.destroy()
        if not self.history:
            tk.Label(self.hist_frame, text="Nothing yet.", font=self.f["small"], bg=C["card"], fg=C["muted"]).pack(anchor="w")
            return
        for subj, res in self.history[:3]:
            phish = res["label"] == "phishing"
            r = tk.Frame(self.hist_frame, bg=C["card"])
            r.pack(fill="x", pady=1)
            tk.Label(r, text="●", font=self.f["small"], bg=C["card"], fg=C["danger"] if phish else C["safe"]).pack(side="left")
            tk.Label(r, text=(subj or "(no subject)")[:46], font=self.f["small"], bg=C["card"], fg=C["ink"]).pack(side="left", padx=6)
            tk.Label(r, text=f"{res['probability']:.0%} · {res['model']}", font=self.f["small"],
                     bg=C["card"], fg=C["muted"]).pack(side="right")

    # ---------------- API calls ----------------
    def _request(self, method, path, payload=None, timeout=30):
        url = self.api_url.get().rstrip("/") + path
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def _run_async(self, work, on_done):
        def runner():
            try:
                result, err = work(), None
            except Exception as exc:  # report every failure in the UI thread
                result, err = None, exc
            self.after(0, lambda: on_done(result, err))
        threading.Thread(target=runner, daemon=True).start()

    def check_health(self):
        self._set_status("Checking API...", C["warn"])

        def done(res, err):
            if err:
                self._set_status("API offline. Start it with  uvicorn api.main:app  (or run_demo.bat)", C["danger"])
            elif res.get("status") != "ok":
                self._set_status(f"API is up but the model is not loaded: {res.get('detail')}", C["danger"])
            else:
                m = res.get("test_metrics") or {}
                extra = f"  ·  test F1 {m['f1']:.3f}, AUC {m['auc_roc']:.4f}" if "f1" in m else ""
                self._set_status(f"Connected  ·  models: {', '.join(res['models'])}{extra}", C["safe"])
        self._run_async(lambda: self._request("GET", "/health", timeout=5), done)

    def analyse(self):
        body = self.body.get("1.0", "end").strip()
        if not body:
            messagebox.showinfo("No email", "Paste an email body or load a .eml file first.")
            return
        if not self.analyse_btn.enabled:
            return
        subject = self.subject.get()
        payload = {"subject": subject, "body": body, "model": self.model_choice.get(), "explain": True, "top_k": 12}
        self.analyse_btn.set_enabled(False, "Analysing...")

        def done(res, err):
            self.analyse_btn.set_enabled(True, "Analyse email   ⏎")
            if err:
                detail = err.read().decode() if isinstance(err, urllib.error.HTTPError) else str(err)
                self._set_status("API offline or returned an error", C["danger"])
                messagebox.showerror("API error", f"Could not analyse the email:\n\n{detail}\n\n"
                                     "Is the API running?  uvicorn api.main:app --reload")
                return
            self.history.insert(0, (subject, res))
            self.show_result(res)
        self._run_async(lambda: self._request("POST", "/predict", payload), done)

    # ---------------- results ----------------
    def show_result(self, res):
        self.last_result = res
        phish = res["label"] == "phishing"
        p = res["probability"]
        bg, fg = (C["danger_bg"], C["danger"]) if phish else (C["safe_bg"], C["safe"])
        for wdg in (self.verdict_box, self.v_icon, self.v_title, self.v_sub, self.v_pct, self.v_title.master):
            wdg.configure(bg=bg)
        self.v_icon.configure(text="⚠" if phish else "✓", fg=fg)
        self.v_title.configure(text="Likely PHISHING" if phish else "Looks LEGITIMATE", fg=fg)
        model_name = "BiLSTM" if res["model"] == "bilstm" else "TF-IDF baseline"
        self.v_sub.configure(text=f"{model_name}  ·  analysed in {res['latency_ms']:.0f} ms", fg=C["muted"])
        self.v_pct.configure(text=f"{p:.0%}", fg=fg)
        for key, lab in self.stat_vals.items():
            lab.configure(text=str(res.get("indicators", {}).get(key, "–")))
        self._draw_gauge()
        self._draw_why()
        self._draw_history()
        self.highlight(res["top_tokens"])

    def highlight(self, tokens):
        """Highlight influential words in the email body (case-insensitive, whole words)."""
        for tag in ("phish", "legit"):
            self.body.tag_remove(tag, "1.0", "end")
        for t in tokens:
            word = t["token"]
            if len(word) < 2 or word.endswith("token"):
                continue  # skip placeholder tokens such as urltoken / numtoken
            tag = "phish" if t["weight"] > 0 else "legit"
            start = "1.0"
            while True:
                count = tk.IntVar()
                pos = self.body.search(rf"\m{word}\M", start, stopindex="end", nocase=True,
                                       regexp=True, count=count)
                if not pos:
                    break
                end = f"{pos}+{count.get()}c"
                self.body.tag_add(tag, pos, end)
                start = end

    # ---------------- input actions ----------------
    def load_eml(self):
        path = filedialog.askopenfilename(title="Open email",
                                          filetypes=[("Email files", "*.eml"), ("Text files", "*.txt"),
                                                     ("All files", "*.*")])
        if not path:
            return
        try:
            if path.lower().endswith(".eml"):
                subject, body = parse_eml(path)
            else:
                with open(path, encoding="utf-8", errors="replace") as f:
                    subject, body = "", f.read()
        except Exception as exc:
            messagebox.showerror("Could not read file", str(exc))
            return
        self._set_email(subject, body)

    def load_sample(self, name):
        self._set_email(*SAMPLES[name])

    def _set_email(self, subject, body):
        self.subject.delete(0, "end")
        self.subject.insert(0, subject)
        self.body.delete("1.0", "end")
        self.body.insert("1.0", body)

    def clear(self):
        self._set_email("", "")
        self.last_result = None
        for wdg in (self.verdict_box, self.v_icon, self.v_title, self.v_sub, self.v_pct, self.v_title.master):
            wdg.configure(bg=C["bg"])
        self.v_icon.configure(text="?", fg=C["muted"])
        self.v_title.configure(text="No email analysed yet", fg=C["ink"])
        self.v_sub.configure(text="Results appear here")
        self.v_pct.configure(text="")
        for lab in self.stat_vals.values():
            lab.configure(text="–")
        self._draw_gauge()
        self._draw_why()


if __name__ == "__main__":
    PhishingApp().mainloop()
