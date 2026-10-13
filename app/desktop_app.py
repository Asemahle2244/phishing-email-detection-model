"""Tkinter desktop app for the phishing email detector.

1. Start the API first (from the project root):   uvicorn api.main:app --reload
2. Then run:                                      python app/desktop_app.py

Uses only the Python standard library (tkinter, urllib, email), so no extra installs.
"""
import json
import threading
import tkinter as tk
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

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

COLORS = {"phishing": "#c62828", "legitimate": "#2e7d32", "neutral": "#455a64",
          "hl_phish": "#ffcdd2", "hl_legit": "#c8e6c9"}


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


class PhishingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Email Detector | ITRI625")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.api_url = tk.StringVar(value=DEFAULT_API)
        self.model_choice = tk.StringVar(value="bilstm")
        self.status = tk.StringVar(value="Checking API...")
        self._build_ui()
        self.after(200, self.check_health)

    # ---------------- layout ----------------
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Verdict.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))
        for name, col in (("Phish", COLORS["phishing"]), ("Legit", COLORS["legitimate"])):
            style.configure(f"{name}.Horizontal.TProgressbar", background=col, troughcolor="#e0e0e0",
                            bordercolor="#bdbdbd", lightcolor=col, darkcolor=col, thickness=18)

        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="API URL:").pack(side="left")
        ttk.Entry(top, textvariable=self.api_url, width=32).pack(side="left", padx=5)
        ttk.Button(top, text="Check connection", command=self.check_health).pack(side="left")
        ttk.Label(top, text="   Model:").pack(side="left")
        ttk.Combobox(top, textvariable=self.model_choice, values=["bilstm", "baseline"],
                     width=10, state="readonly").pack(side="left", padx=5)
        self.status_label = ttk.Label(top, textvariable=self.status, foreground=COLORS["neutral"])
        self.status_label.pack(side="right")

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # left: input
        left = ttk.Frame(main, padding=5)
        main.add(left, weight=3)
        ttk.Label(left, text="Subject", style="Header.TLabel").pack(anchor="w")
        self.subject = ttk.Entry(left, font=("Segoe UI", 10))
        self.subject.pack(fill="x", pady=(0, 6))
        ttk.Label(left, text="Email body", style="Header.TLabel").pack(anchor="w")
        self.body = ScrolledText(left, wrap="word", font=("Consolas", 10), undo=True)
        self.body.pack(fill="both", expand=True)
        self.body.tag_configure("phish", background=COLORS["hl_phish"])
        self.body.tag_configure("legit", background=COLORS["hl_legit"])

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=6)
        self.analyse_btn = ttk.Button(btns, text="Analyse email", command=self.analyse)
        self.analyse_btn.pack(side="left")
        ttk.Button(btns, text="Load .eml file...", command=self.load_eml).pack(side="left", padx=5)
        sample_menu = ttk.Menubutton(btns, text="Load sample")
        menu = tk.Menu(sample_menu, tearoff=False)
        for name in SAMPLES:
            menu.add_command(label=name, command=lambda n=name: self.load_sample(n))
        sample_menu["menu"] = menu
        sample_menu.pack(side="left")
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="right")
        self.bind("<Control-Return>", lambda _e: self.analyse())

        # right: results
        right = ttk.Frame(main, padding=10)
        main.add(right, weight=2)
        ttk.Label(right, text="Result", style="Header.TLabel").pack(anchor="w")
        self.verdict = ttk.Label(right, text="-", style="Verdict.TLabel", foreground=COLORS["neutral"])
        self.verdict.pack(anchor="w", pady=(4, 2))
        self.prob_text = ttk.Label(right, text="Paste an email and click Analyse (Ctrl+Enter).")
        self.prob_text.pack(anchor="w")
        self.prob_bar = ttk.Progressbar(right, maximum=100, length=320)
        self.prob_bar.pack(fill="x", pady=(6, 2))
        self.threshold_text = ttk.Label(right, text="", foreground=COLORS["neutral"])
        self.threshold_text.pack(anchor="w")

        ttk.Separator(right).pack(fill="x", pady=10)
        ttk.Label(right, text="Why? Most influential words", style="Header.TLabel").pack(anchor="w")
        ttk.Label(right, text="Red words push towards phishing, green words towards legitimate. "
                              "Weight = change in the model's log-odds when the word is removed.",
                  foreground=COLORS["neutral"], wraplength=380, justify="left").pack(anchor="w")
        cols = ("token", "weight", "direction")
        self.tokens = ttk.Treeview(right, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (150, 80, 110)):
            self.tokens.heading(c, text=c.capitalize())
            self.tokens.column(c, width=w, anchor="w")
        self.tokens.tag_configure("phish", foreground=COLORS["phishing"])
        self.tokens.tag_configure("legit", foreground=COLORS["legitimate"])
        self.tokens.pack(fill="both", expand=True, pady=4)

        ttk.Label(right, text="Indicators", style="Header.TLabel").pack(anchor="w", pady=(8, 0))
        self.indicators = ttk.Label(right, text="", justify="left")
        self.indicators.pack(anchor="w")

    # ---------------- actions ----------------
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
        self.status.set("Checking API...")

        def done(res, err):
            if err:
                self.status.set("API offline: start it with  uvicorn api.main:app")
                self.status_label.configure(foreground=COLORS["phishing"])
            elif res.get("status") != "ok":
                self.status.set(f"API up, model not loaded: {res.get('detail')}")
                self.status_label.configure(foreground=COLORS["phishing"])
            else:
                f1 = (res.get("test_metrics") or {}).get("f1")
                self.status.set(f"Connected | models: {', '.join(res['models'])}"
                                + (f" | test F1 {f1:.3f}" if f1 else ""))
                self.status_label.configure(foreground=COLORS["legitimate"])
        self._run_async(lambda: self._request("GET", "/health", timeout=5), done)

    def analyse(self):
        body = self.body.get("1.0", "end").strip()
        if not body:
            messagebox.showinfo("No email", "Paste an email body or load a .eml file first.")
            return
        payload = {"subject": self.subject.get(), "body": body,
                   "model": self.model_choice.get(), "explain": True, "top_k": 12}
        self.analyse_btn.configure(state="disabled", text="Analysing...")

        def done(res, err):
            self.analyse_btn.configure(state="normal", text="Analyse email")
            if err:
                detail = err.read().decode() if isinstance(err, urllib.error.HTTPError) else str(err)
                messagebox.showerror("API error", f"Could not analyse the email:\n\n{detail}\n\n"
                                     "Is the API running?  uvicorn api.main:app --reload")
                return
            self.show_result(res)
        self._run_async(lambda: self._request("POST", "/predict", payload), done)

    def show_result(self, res):
        is_phish = res["label"] == "phishing"
        color = COLORS["phishing"] if is_phish else COLORS["legitimate"]
        self.verdict.configure(text="PHISHING" if is_phish else "LEGITIMATE", foreground=color)
        p = res["probability"]
        self.prob_text.configure(text=f"P(phishing) = {p:.1%}   ({res['model']}, {res['latency_ms']:.0f} ms)")
        self.prob_bar.configure(style=("Phish" if is_phish else "Legit") + ".Horizontal.TProgressbar")
        self.prob_bar["value"] = p * 100
        self.threshold_text.configure(text=f"Decision threshold: {res['threshold']:.3f}")

        self.tokens.delete(*self.tokens.get_children())
        for t in res["top_tokens"]:
            tag = "phish" if t["weight"] > 0 else "legit"
            self.tokens.insert("", "end", values=(t["token"], f"{t['weight']:+.4f}",
                                                  "phishing" if tag == "phish" else "legitimate"), tags=(tag,))
        ind = res.get("indicators", {})
        self.indicators.configure(text=f"URLs found: {ind.get('url_count', 0)}\n"
                                       f"Words: {ind.get('word_count', 0)}\n"
                                       f"Exclamation marks: {ind.get('exclamation_marks', 0)}")
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
        self.verdict.configure(text="-", foreground=COLORS["neutral"])
        self.prob_text.configure(text="Paste an email and click Analyse (Ctrl+Enter).")
        self.prob_bar["value"] = 0
        self.threshold_text.configure(text="")
        self.tokens.delete(*self.tokens.get_children())
        self.indicators.configure(text="")


if __name__ == "__main__":
    PhishingApp().mainloop()
