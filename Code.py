
import atexit
import base64
import ctypes
import hmac          # FIX-1: constant-time comparison
import json
import os
import platform
import secrets       # sole source of randomness
import string
import sys
import threading
import time
import tkinter as tk
import uuid
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
#  THIRD-PARTY
# ─────────────────────────────────────────────────────────────────────────────
try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError:
    sys.exit(
        "\n[FATAL] argon2-cffi is not installed.\n"
        "  Run:  pip install argon2-cffi\n"
    )

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit(
        "\n[FATAL] cryptography is not installed.\n"
        "  Run:  pip install cryptography\n"
    )


# ═════════════════════════════════════════════════════════════════════════════
#  LAYER 3 — CRYPTOGRAPHIC ENGINE  (Black Box)
# ═════════════════════════════════════════════════════════════════════════════

KDF_MEMORY_COST   = 8_192     # 8 MB  — fast on any PC (~0.1-0.3s unlock)
KDF_TIME_COST     = 1         # 1 iteration
KDF_PARALLELISM   = 1         # 1 thread
KDF_KEY_LEN       = 32        # 256-bit
MASTER_SALT_LEN   = 16        # 16-byte global salt
ENTRY_SALT_LEN    = 16        # 16-byte per-entry salt
NONCE_LEN         = 12        # 96-bit GCM nonce

KDF_PARAMS: dict = {
    "algorithm":   "argon2id",
    "version":     19,
    "memory_kb":   KDF_MEMORY_COST,
    "iterations":  KDF_TIME_COST,
    "parallelism": KDF_PARALLELISM,
    "key_len":     KDF_KEY_LEN,
    "salt_len":    MASTER_SALT_LEN,
}

# Fixed domain-separation salt for key-hash (never changes; changing it
# invalidates all vaults).
_KEY_HASH_SALT: bytes = b"pm-v3-key-verif\x00"   # 16 bytes


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    """
    FIX-8: Validate base64 input before decoding.
    Raises ValueError on malformed data rather than crashing opaquely.
    """
    try:
        data = base64.b64decode(s, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 in vault data: {exc}") from exc
    return data


def _rand_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes via secrets/os.urandom."""
    return secrets.token_bytes(n)


# ── RAM Zeroing ───────────────────────────────────────────────────────────────

def zero_bytes(buf) -> None:
    """
    FIX-3 (clarified): Overwrite buffer contents with zeros.

    IMPORTANT PYTHON LIMITATION:
    Python strings are IMMUTABLE objects.  When a caller does:
        zero_bytes(bytearray(some_str.encode()))
    …the NEW bytearray is zeroed, but the original str object in CPython's
    string intern pool / reference table is NOT affected.
    The only reliable mitigation is to minimise how long secrets live as Python
    str objects.  Sensitive data is moved to bytearray as early as possible.

    This function reliably zeroes bytearray objects.
    For bytes/memoryview it uses a CPython-specific ctypes trick (best-effort).
    """
    if buf is None:
        return
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
        return
    # Best-effort for immutable types (CPython only)
    try:
        if isinstance(buf, str):
            buf = buf.encode("utf-8")
        if isinstance(buf, (bytes, memoryview)):
            nbytes = len(buf)
            # Locate the ob_val field inside the CPython bytes struct
            addr = id(buf) + sys.getsizeof(b"") - nbytes
            ctypes.memset(addr, 0, nbytes)
    except Exception:
        pass  # Non-CPython runtimes: silently skip


# ── KDF & Encryption ──────────────────────────────────────────────────────────

def derive_master_key(password: str, master_salt: bytes) -> bytearray:
    """Argon2id KDF → 256-bit master key.  Caller MUST zero_bytes() result."""
    raw = hash_secret_raw(
        secret      = password.encode("utf-8"),
        salt        = master_salt,
        time_cost   = KDF_TIME_COST,
        memory_cost = KDF_MEMORY_COST,
        parallelism = KDF_PARALLELISM,
        hash_len    = KDF_KEY_LEN,
        type        = Type.ID,
    )
    return bytearray(raw)


def hash_master_key(key: bytearray) -> str:
    """
    Argon2id(derived_key, fixed_salt) → Base64.
    Stored in vault header; used ONLY for login verification.
    The raw key and password are never stored.
    """
    digest = hash_secret_raw(
        secret      = bytes(key),
        salt        = _KEY_HASH_SALT,
        time_cost   = 1,
        memory_cost = 8_192,
        parallelism = 1,
        hash_len    = 32,
        type        = Type.ID,
    )
    return _b64e(digest)


def derive_entry_key(master_key: bytearray, entry_salt: bytes) -> bytearray:
    """
    Per-entry 256-bit key derived from master key + unique entry salt.
    Compromising one entry key reveals nothing about other entries.
    Caller MUST zero_bytes() the result.
    """
    # Build a domain-separated secret; zero it immediately after use
    secret_ba = bytearray(bytes(master_key).hex().encode("utf-8") + b"entry-v3")
    raw = hash_secret_raw(
        secret      = bytes(secret_ba),
        salt        = entry_salt,
        time_cost   = 1,
        memory_cost = 8_192,
        parallelism = 1,
        hash_len    = KDF_KEY_LEN,
        type        = Type.ID,
    )
    zero_bytes(secret_ba)   # zero the intermediate bytearray (reliable)
    return bytearray(raw)


def encrypt_payload(entry_key: bytearray, plaintext: str) -> tuple[bytes, bytes]:
    """AES-256-GCM. Returns (ciphertext+tag, nonce)."""
    nonce  = _rand_bytes(NONCE_LEN)
    aesgcm = AESGCM(bytes(entry_key))
    ct     = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ct, nonce


def decrypt_payload(entry_key: bytearray, ciphertext: bytes, nonce: bytes) -> str:
    """
    AES-256-GCM decryption with integrity check.
    Raises InvalidTag if vault has been tampered with (even 1 bit changed).
    """
    aesgcm    = AESGCM(bytes(entry_key))
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def generate_password(length: int = 20,
                       upper: bool = True,
                       digits: bool = True,
                       symbols: bool = True) -> str:
    """
    FIX-10: Cryptographically strong password generator.

    Uses only secrets.choice() in an explicit loop.
    No SystemRandom.shuffle() (which exposed random module internals).
    Guarantees at least one character from every enabled character class.
    """
    pool: str     = string.ascii_lowercase
    required: list[str] = [secrets.choice(string.ascii_lowercase)]

    if upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        sym  = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pool += sym
        required.append(secrets.choice(sym))

    # Fill remaining positions, then shuffle using Fisher-Yates via secrets
    result: list[str] = required + [
        secrets.choice(pool) for _ in range(length - len(required))
    ]
    # FIX-10: Pure secrets-based Fisher-Yates shuffle (no random.shuffle)
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]

    return "".join(result)


# ═════════════════════════════════════════════════════════════════════════════
#  LAYER 4 — PERSISTENCE  (Atomic I/O + File Permissions)
# ═════════════════════════════════════════════════════════════════════════════

# FIX-5: Vault path anchored to the SCRIPT'S directory, not CWD.
# This ensures vault.json is always found even if the user launches
# the script from a different directory.
VAULT_FILE: Path = Path(__file__).resolve().parent / "vault.json"

_IS_WINDOWS: bool = platform.system() == "Windows"


def vault_exists() -> bool:
    return VAULT_FILE.exists()


# ── Schema validation ──────────────────────────────────────────────────────────

# FIX-7: Validate vault structure before trusting any field.
# An attacker who modifies vault.json manually would be caught here.
_REQUIRED_META_KEYS  = {"version", "master_salt", "master_hash", "kdf_params"}
_REQUIRED_ENTRY_KEYS = {"id", "name", "url", "encrypted_payload",
                         "entry_salt", "nonce", "created_at", "modified_at"}


def _validate_vault(vault: dict) -> None:
    """
    FIX-7: Raise ValueError if vault JSON structure is invalid or incomplete.
    Prevents KeyError/AttributeError crashes on tampered files.
    """
    if not isinstance(vault, dict):
        raise ValueError("Vault root is not a JSON object.")
    if "meta" not in vault or "entries" not in vault:
        raise ValueError("Vault missing 'meta' or 'entries' keys.")
    meta = vault["meta"]
    missing_meta = _REQUIRED_META_KEYS - set(meta.keys())
    if missing_meta:
        raise ValueError(f"Vault meta missing keys: {missing_meta}")
    if not isinstance(vault["entries"], list):
        raise ValueError("Vault 'entries' is not a list.")
    for i, entry in enumerate(vault["entries"]):
        missing_entry = _REQUIRED_ENTRY_KEYS - set(entry.keys())
        if missing_entry:
            raise ValueError(
                f"Entry #{i} (id={entry.get('id','?')}) "
                f"missing keys: {missing_entry}"
            )
        # Validate salt/nonce lengths to detect truncation attacks
        try:
            salt_bytes  = _b64d(entry["entry_salt"])
            nonce_bytes = _b64d(entry["nonce"])
        except ValueError as exc:
            raise ValueError(f"Entry #{i} corrupt base64: {exc}") from exc
        if len(salt_bytes)  != ENTRY_SALT_LEN:
            raise ValueError(
                f"Entry #{i} entry_salt wrong length "
                f"(got {len(salt_bytes)}, expected {ENTRY_SALT_LEN})"
            )
        if len(nonce_bytes) != NONCE_LEN:
            raise ValueError(
                f"Entry #{i} nonce wrong length "
                f"(got {len(nonce_bytes)}, expected {NONCE_LEN})"
            )


def _read() -> dict:
    """Read and validate vault.json."""
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as fh:
            vault = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"vault.json is not valid JSON: {exc}") from exc
    _validate_vault(vault)
    return vault


def _write(vault: dict) -> None:
    """
    FIX-2 + FIX-5: Atomic write with restrictive file permissions.

    Steps:
      1. Write to a .tmp file
      2. Set permissions to owner-only (0o600) on POSIX
      3. Atomically rename .tmp → vault.json
    """
    tmp = VAULT_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(vault, fh, indent=2, ensure_ascii=False)

    # FIX-2: Restrict file to owner read/write only
    if not _IS_WINDOWS:
        os.chmod(tmp, 0o600)   # rw------- on Linux/macOS
    # Atomic rename (POSIX: atomic; Windows: best-effort)
    tmp.replace(VAULT_FILE)
    if not _IS_WINDOWS:
        os.chmod(VAULT_FILE, 0o600)


def create_vault(password: str) -> None:
    """Initialise a new vault with an empty entry list."""
    salt = _rand_bytes(MASTER_SALT_LEN)
    key  = derive_master_key(password, salt)
    kh   = hash_master_key(key)
    zero_bytes(key)

    vault = {
        "meta": {
            "version":     3,
            "master_salt": _b64e(salt),
            "master_hash": kh,
            "kdf_params":  KDF_PARAMS,
        },
        "entries": [],
    }
    _write(vault)


def verify_and_load_key(password: str) -> Optional[bytearray]:
    """
    Derive master key and verify against stored hash.

    FIX-1: Uses hmac.compare_digest() for CONSTANT-TIME comparison.
    A plain `==` comparison leaks timing information about how many bytes
    of the hash match — hmac.compare_digest() always takes the same time.

    Returns: bytearray key on success.  None on failure.
    Caller MUST zero_bytes() the key when done.
    """
    try:
        meta = _read()["meta"]
    except ValueError:
        return None

    try:
        salt = _b64d(meta["master_salt"])
    except ValueError:
        return None

    key = derive_master_key(password, salt)
    kh  = hash_master_key(key)

    # FIX-1: constant-time comparison — prevents timing attacks
    if hmac.compare_digest(kh, meta["master_hash"]):
        return key

    zero_bytes(key)
    return None


def storage_list_entries() -> list[dict]:
    """
    Return all entries.
    Only plaintext name/url are accessed — encrypted_payload untouched.
    """
    try:
        return _read()["entries"]
    except ValueError:
        return []


def storage_add_entry(master_key: bytearray,
                       name: str, url: str,
                       username: str, password: str, notes: str) -> str:
    entry_salt = _rand_bytes(ENTRY_SALT_LEN)
    entry_key  = derive_entry_key(master_key, entry_salt)

    payload   = json.dumps({"username": username,
                             "password": password,
                             "notes":    notes},
                            ensure_ascii=False)
    ct, nonce = encrypt_payload(entry_key, payload)
    zero_bytes(entry_key)

    eid   = str(uuid.uuid4())
    now   = int(time.time())
    vault = _read()
    vault["entries"].append({
        "id":                eid,
        "name":              name,
        "url":               url,
        "encrypted_payload": _b64e(ct),
        "entry_salt":        _b64e(entry_salt),
        "nonce":             _b64e(nonce),
        "created_at":        now,
        "modified_at":       now,
    })
    _write(vault)
    return eid


def storage_decrypt_entry(master_key: bytearray,
                            entry_id: str) -> Optional[dict]:
    """On-the-fly decryption.  Detects tamper via GCM auth tag."""
    try:
        entries = _read()["entries"]
    except ValueError:
        return None

    for e in entries:
        if e["id"] != entry_id:
            continue
        entry_key = None   # B1 FIX: always defined so finally never raises NameError
        try:
            entry_key = derive_entry_key(master_key, _b64d(e["entry_salt"]))
            raw       = decrypt_payload(entry_key,
                                         _b64d(e["encrypted_payload"]),
                                         _b64d(e["nonce"]))
            result    = json.loads(raw)
        except (InvalidTag, ValueError, KeyError):
            return None
        finally:
            zero_bytes(entry_key)
        result.update({"id": e["id"], "name": e["name"], "url": e["url"]})
        return result
    return None


def storage_update_entry(master_key: bytearray, entry_id: str,
                          name: str, url: str,
                          username: str, password: str, notes: str) -> bool:
    try:
        vault = _read()
    except ValueError:
        return False

    for e in vault["entries"]:
        if e["id"] != entry_id:
            continue
        entry_salt = _rand_bytes(ENTRY_SALT_LEN)   # rotate salt on every edit
        entry_key  = derive_entry_key(master_key, entry_salt)
        payload    = json.dumps({"username": username,
                                  "password": password,
                                  "notes":    notes},
                                 ensure_ascii=False)
        ct, nonce  = encrypt_payload(entry_key, payload)
        zero_bytes(entry_key)

        e["name"]              = name
        e["url"]               = url
        e["encrypted_payload"] = _b64e(ct)
        e["entry_salt"]        = _b64e(entry_salt)
        e["nonce"]             = _b64e(nonce)
        e["modified_at"]       = int(time.time())
        _write(vault)
        return True
    return False


def storage_delete_entry(entry_id: str) -> bool:
    try:
        vault = _read()
    except ValueError:
        return False
    before         = len(vault["entries"])
    vault["entries"] = [e for e in vault["entries"] if e["id"] != entry_id]
    if len(vault["entries"]) < before:
        _write(vault)
        return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
#  LAYER 2 — BUSINESS LOGIC
# ═════════════════════════════════════════════════════════════════════════════

DEAD_WAIT_SECS      = 2
CLIPBOARD_CLEAR_SEC = 30
AUTO_LOCK_SEC       = 300    # FIX-4: 5-minute idle auto-lock


class Session:
    """
    Holds master key in RAM for the duration of a logged-in session.

    Key is a mutable bytearray and is zeroed on logout.

    FIX-4: An idle timer auto-locks the vault after AUTO_LOCK_SEC seconds
           of inactivity to protect an unattended, unlocked screen.

    FIX-9: __del__ removed.  Cleanup is handled by an atexit hook registered
           at login time, which is reliable even at interpreter shutdown.
    """

    def __init__(self):
        self._key: Optional[bytearray]             = None
        self._cb_timer: Optional[threading.Timer]  = None
        self._lock_timer: Optional[threading.Timer]= None
        self._on_auto_lock_cb                      = None
        self._atexit_registered: bool              = False  # B7 FIX

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self, password: str) -> bool:
        """
        Derive and verify key.
        Blocks for DEAD_WAIT_SECS on failure (anti-brute-force dead-wait).
        """
        key = verify_and_load_key(password)
        if key is None:
            time.sleep(DEAD_WAIT_SECS)
            return False
        self._key = key
        # B7 FIX: only register atexit once — multiple logins previously
        # caused _atexit_cleanup to be registered and called multiple times.
        if not self._atexit_registered:
            atexit.register(self._atexit_cleanup)
            self._atexit_registered = True
        self._reset_lock_timer()
        return True

    def logout(self) -> None:
        """Zero the master key and cancel all background timers."""
        zero_bytes(self._key)
        self._key = None
        self._cancel_cb_timer()
        self._cancel_lock_timer()

    def _atexit_cleanup(self) -> None:
        """FIX-9: Called by atexit — zeroes key at interpreter shutdown."""
        try:
            zero_bytes(self._key)
            self._key = None
        except Exception:
            pass

    @property
    def active(self) -> bool:
        return self._key is not None

    def _assert_auth(self) -> None:
        if not self.active:
            raise PermissionError("Session is not authenticated.")

    def touch(self) -> None:
        """
        FIX-4: Reset the idle auto-lock countdown.
        Call on any user interaction (keystroke, mouse click, etc.).
        """
        if self.active:
            self._reset_lock_timer()

    # ── Entry CRUD ────────────────────────────────────────────────────────

    def add(self, name, url, username, password, notes) -> str:
        self._assert_auth(); self.touch()
        return storage_add_entry(self._key, name, url, username, password, notes)

    def decrypt(self, entry_id: str) -> Optional[dict]:
        self._assert_auth(); self.touch()
        return storage_decrypt_entry(self._key, entry_id)

    def update(self, entry_id, name, url, username, password, notes) -> bool:
        self._assert_auth(); self.touch()
        return storage_update_entry(self._key, entry_id, name, url,
                                     username, password, notes)

    def delete(self, entry_id: str) -> bool:
        self._assert_auth(); self.touch()
        return storage_delete_entry(entry_id)

    # ── Clipboard management ──────────────────────────────────────────────

    def copy_to_clipboard(self, root: tk.Tk, text: str) -> None:
        """Copy *text* to clipboard. Schedule auto-wipe after CLIPBOARD_CLEAR_SEC."""
        root.clipboard_clear()
        root.clipboard_append(text)
        # NOTE: no root.update() here — it is called from the main thread
        # so the clipboard write is immediate; update() is unnecessary.
        self._cancel_cb_timer()
        self._cb_timer = threading.Timer(
            CLIPBOARD_CLEAR_SEC, self._wipe_clipboard, args=(root, text)
        )
        self._cb_timer.daemon = True
        self._cb_timer.start()
        self.touch()

    def _wipe_clipboard(self, root: tk.Tk, original: str) -> None:
        # THREADING FIX: runs in a Timer background thread.
        # Tkinter is NOT thread-safe. Marshal ALL tk calls to the main thread
        # via root.after(0, ...) — never call clipboard/update from here directly.
        def _do_wipe():
            try:
                root.clipboard_clear()
                root.clipboard_append("")
            except Exception:
                pass
        try:
            root.after(0, _do_wipe)
        except Exception:
            pass
        finally:
            zero_bytes(bytearray(original.encode("utf-8")))

    def _cancel_cb_timer(self) -> None:
        if self._cb_timer and self._cb_timer.is_alive():
            self._cb_timer.cancel()
        self._cb_timer = None

    # ── Auto-lock timer ───────────────────────────────────────────────────

    def _reset_lock_timer(self) -> None:
        """FIX-4: (Re)start the idle auto-lock countdown."""
        self._cancel_lock_timer()
        self._lock_timer = threading.Timer(
            AUTO_LOCK_SEC, self._trigger_auto_lock
        )
        self._lock_timer.daemon = True
        self._lock_timer.start()

    def _cancel_lock_timer(self) -> None:
        if self._lock_timer and self._lock_timer.is_alive():
            self._lock_timer.cancel()
        self._lock_timer = None

    def _trigger_auto_lock(self) -> None:
        """FIX-4: Called by idle timer. Zeroes key and notifies GUI."""
        self.logout()
        if callable(self._on_auto_lock_cb):
            try:
                self._on_auto_lock_cb()
            except Exception:
                pass


# ═════════════════════════════════════════════════════════════════════════════
#  LAYER 1 — PRESENTATION  (Tkinter GUI)
# ═════════════════════════════════════════════════════════════════════════════

_C = {
    "bg":      "#0d0f14",
    "panel":   "#13161d",
    "border":  "#1e2330",
    "accent":  "#00d4ff",
    "accent2": "#ff4757",
    "fg":      "#dce3f0",
    "fg2":     "#5a6480",
    "fg3":     "#8892aa",
    "input":   "#0a0c11",
    "success": "#00e676",
    "warning": "#ffab40",
    "btn":     "#1a1f2e",
    "btn_h":   "#252c3f",
}

_F  = ("Consolas", 10)
_FB = ("Consolas", 10, "bold")
_FH = ("Consolas", 13, "bold")
_FS = ("Consolas", 9)
_FT = ("Consolas", 17, "bold")


def _apply_theme(root: tk.Tk) -> None:
    root.configure(bg=_C["bg"])
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=_C["bg"], foreground=_C["fg"],
                font=_F, borderwidth=0, relief="flat",
                fieldbackground=_C["input"])
    s.configure("TFrame", background=_C["bg"])
    s.configure("TLabel", background=_C["bg"], foreground=_C["fg"])
    s.configure("TEntry",
        fieldbackground=_C["input"], foreground=_C["fg"],
        insertcolor=_C["accent"], borderwidth=1, relief="flat")
    s.configure("TScrollbar",
        background=_C["border"], troughcolor=_C["bg"],
        arrowcolor=_C["fg2"], width=8)
    s.configure("Treeview",
        background=_C["panel"], foreground=_C["fg"],
        fieldbackground=_C["panel"], rowheight=30, borderwidth=0)
    s.configure("Treeview.Heading",
        background=_C["border"], foreground=_C["accent"],
        font=_FB, relief="flat")
    s.map("Treeview",
        background=[("selected", _C["accent"])],
        foreground=[("selected", _C["bg"])])
    s.configure("Accent.TButton",
        background=_C["accent"], foreground=_C["bg"],
        font=_FB, padding=(12, 6), relief="flat")
    s.map("Accent.TButton",
        background=[("active", "#00b8d9"), ("disabled", _C["border"])])
    s.configure("Danger.TButton",
        background=_C["accent2"], foreground="white",
        font=_FB, padding=(10, 5), relief="flat")
    s.map("Danger.TButton",
        background=[("active", "#cc2233")])
    s.configure("Ghost.TButton",
        background=_C["btn"], foreground=_C["fg3"],
        font=_F, padding=(8, 4), relief="flat")
    s.map("Ghost.TButton",
        background=[("active", _C["btn_h"])],
        foreground=[("active", _C["fg"])])
    s.configure("TCheckbutton",
        background=_C["bg"], foreground=_C["fg3"])
    s.map("TCheckbutton", background=[("active", _C["bg"])])


def _center(win, w: int, h: int) -> None:
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


def _sep(parent) -> tk.Frame:
    return tk.Frame(parent, height=1, bg=_C["border"])


def _lbl(parent, text="", color=None, font=None, **kw) -> ttk.Label:
    cfg = {}
    if color: cfg["foreground"] = color
    if font:  cfg["font"]       = font
    return ttk.Label(parent, text=text, **cfg, **kw)


def _entry(parent, show=None, width=30, **kw) -> ttk.Entry:
    return ttk.Entry(parent, show=show, width=width, **kw)


def _btn(parent, text, cmd, style="Ghost.TButton", **kw) -> ttk.Button:
    return ttk.Button(parent, text=text, command=cmd, style=style, **kw)


def _toast(root: tk.Tk, message: str, ms: int = 1000) -> None:
    """
    Tiny floating notification that auto-dismisses after `ms` milliseconds.
    MUST be called from the main thread only.
    No root.update() — uses root.after() for the dismiss timer.
    """
    try:
        t = tk.Toplevel(root)
        t.overrideredirect(True)       # no title bar
        t.attributes("-topmost", True)
        t.configure(bg=_C["accent"])   # 1-px accent border effect via bg

        root.update_idletasks()
        rx = root.winfo_rootx() + root.winfo_width()  - 240
        ry = root.winfo_rooty() + root.winfo_height() - 58
        t.geometry(f"232x32+{rx}+{ry}")

        inner = tk.Frame(t, bg=_C["panel"], padx=10, pady=0)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        tk.Label(
            inner,
            text=f"  \u2713  {message}",
            bg=_C["panel"],
            fg=_C["accent"],
            font=("Consolas", 9),
            anchor="w",
        ).pack(fill="both", expand=True)

        # Schedule dismiss on main thread — never call t.destroy() from a thread
        root.after(ms, lambda: t.destroy() if t.winfo_exists() else None)
    except Exception:
        pass  # never crash the app over a toast


# ─────────────────────────────────────────────────────────────────────────────
#  Setup Dialog  (first-run vault creation)
# ─────────────────────────────────────────────────────────────────────────────

class SetupDialog(tk.Toplevel):

    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.title("Initialize Vault")
        self.configure(bg=_C["bg"])
        self.resizable(False, False)
        _center(self, 440, 400)
        self.grab_set()
        self.result = False
        self._build()

    def _build(self):
        tk.Frame(self, bg=_C["accent"], height=2).pack(fill="x")
        hdr = tk.Frame(self, bg=_C["panel"])
        hdr.pack(fill="x")
        _lbl(hdr, "  ⬡  INITIALIZE VAULT", font=_FT,
             color=_C["accent"]).pack(anchor="w", padx=20, pady=14)
        tk.Frame(self, bg=_C["border"], height=1).pack(fill="x")

        p = dict(padx=32, pady=5)
        _lbl(self,
             "Create a master password to encrypt your vault.\n"
             "It cannot be recovered if lost.  Minimum 5 characters.",
             color=_C["fg2"], font=_FS).pack(**p)

        f = ttk.Frame(self); f.pack(fill="x", padx=32)
        f.columnconfigure(0, weight=1)

        _lbl(f, "Master Password", color=_C["fg3"], font=_FS).grid(
            row=0, sticky="w", pady=(8, 2))
        self._pw1 = _entry(f, show="●", width=34)
        self._pw1.grid(row=1, sticky="ew")

        _lbl(f, "Confirm Password", color=_C["fg3"], font=_FS).grid(
            row=2, sticky="w", pady=(8, 2))
        self._pw2 = _entry(f, show="●", width=34)
        self._pw2.grid(row=3, sticky="ew")

        # B4 FIX: tk.Label (not ttk via _lbl) so textvariable always renders
        self._str_var = tk.StringVar()
        self._str_lbl = tk.Label(self, textvariable=self._str_var,
                                  bg=_C["bg"], fg=_C["fg2"],
                                  font=_FS, anchor="w")
        self._str_lbl.pack(padx=32, anchor="w", pady=2)
        self._pw1.bind("<KeyRelease>", self._on_key)

        self._err = _lbl(self, color=_C["accent2"], font=_FS)
        self._err.pack(padx=32, anchor="w")

        _btn(self, "  CREATE VAULT  ", self._submit,
             style="Accent.TButton").pack(pady=16)
        self._pw1.focus_set()
        self.bind("<Return>", lambda _: self._submit())

    def _on_key(self, _=None):
        pw    = self._pw1.get()
        score = sum([
            len(pw) >= 5,
            len(pw) >= 20,
            any(c.isupper()  for c in pw),
            any(c.isdigit()  for c in pw),
            any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw),
        ])
        labels = ["", "● WEAK", "●● FAIR", "●●● GOOD",
                  "●●●● STRONG", "●●●●● EXCELLENT"]
        colors = ["", _C["accent2"], _C["warning"], _C["fg3"],
                  _C["success"], _C["accent"]]
        # B5 FIX: actually apply the color — previously defined but never used
        self._str_var.set(labels[score] if score else "")
        self._str_lbl.config(fg=colors[score] if score else _C["fg2"])

    def _submit(self):
        p1 = self._pw1.get(); p2 = self._pw2.get()
        if len(p1) < 5:
            self._err.config(text="Password must be at least 5 characters."); return
        if p1 != p2:
            self._err.config(text="Passwords do not match."); return
        self._err.config(text="⏳  Deriving key…")
        self.update()
        create_vault(p1)
        # Best-effort zero — Python str limitation noted in zero_bytes()
        zero_bytes(bytearray(p1.encode())); zero_bytes(bytearray(p2.encode()))
        self.result = True
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
#  Lock Screen
# ─────────────────────────────────────────────────────────────────────────────

class LockScreen(tk.Toplevel):

    def __init__(self, master: tk.Tk, session: Session):
        super().__init__(master)
        self.title("Vault Locked")
        self.configure(bg=_C["bg"])
        self.resizable(False, False)
        _center(self, 400, 285)
        self.grab_set()
        self.session  = session
        self.unlocked = False
        self._build()

    def _build(self):
        tk.Frame(self, bg=_C["accent"], height=2).pack(fill="x")
        tk.Frame(self, height=18, bg=_C["bg"]).pack()
        _lbl(self, "  \U0001f512  VAULT LOCKED", font=_FT,
             color=_C["accent"]).pack(padx=28, anchor="w")
        tk.Frame(self, height=4, bg=_C["bg"]).pack()
        _sep(self).pack(fill="x", padx=28)
        tk.Frame(self, height=10, bg=_C["bg"]).pack()

        f = ttk.Frame(self); f.pack(fill="x", padx=28)
        _lbl(f, "MASTER PASSWORD", color=_C["fg2"], font=_FS).pack(anchor="w")
        self._pw_var = tk.StringVar()
        pw_e = _entry(f, show="\u25cf", textvariable=self._pw_var, width=36)
        pw_e.pack(fill="x", pady=(4, 0))
        pw_e.focus_set()

        # ── Warning banner ─────────────────────────────────────────────────
        # Fixed-height container so layout never shifts.
        # Background turns solid red on wrong password.
        banner_wrap = tk.Frame(self, bg=_C["bg"], height=34)
        banner_wrap.pack(fill="x", padx=28, pady=(8, 0))
        banner_wrap.pack_propagate(False)

        self._banner = tk.Frame(banner_wrap, bg=_C["bg"])
        self._banner.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._msg = tk.Label(
            self._banner,
            text="",                        # empty until wrong password
            bg=_C["bg"],
            fg=_C["bg"],                    # invisible until needed
            font=("Consolas", 10, "bold"),
            anchor="center",
        )
        self._msg.pack(fill="both", expand=True)
        # ──────────────────────────────────────────────────────────────────

        bf = ttk.Frame(self); bf.pack(padx=28, pady=8, anchor="w")
        _btn(bf, "  UNLOCK  ", self._submit,
             style="Accent.TButton").pack(side="left", padx=(0, 8))
        _btn(bf, "Cancel", self.destroy).pack(side="left")
        self.bind("<Return>", lambda _: self._submit())

    def _submit(self):
        pw = self._pw_var.get()
        self._pw_var.set("")

        # Reset banner to neutral before each attempt
        self._banner.config(bg=_C["bg"])
        self._msg.config(text="\u23f3  Verifying\u2026",
                         fg=_C["fg2"], bg=_C["bg"])
        self.update_idletasks()          # flush UI — safe, still on main thread

        def _auth():
            ok = self.session.login(pw)  # blocks 2s on failure (dead-wait)
            zero_bytes(bytearray(pw.encode()))
            if ok:
                self.unlocked = True
                self.after(0, self.destroy)
            else:
                # MUST use after() — tk widgets cannot be touched from threads
                def _show_err():
                    try:
                        self._banner.config(bg=_C["accent2"])
                        self._msg.config(
                            text="  \u26a0  WRONG PASSWORD \u2014 try again  \u26a0  ",
                            fg="white",
                            bg=_C["accent2"],
                        )
                    except Exception:
                        pass
                self.after(0, _show_err)

        threading.Thread(target=_auth, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
#  Add / Edit Entry Dialog
# ─────────────────────────────────────────────────────────────────────────────

class EntryDialog(tk.Toplevel):

    def __init__(self, master: tk.Tk, session: Session,
                 entry_id: Optional[str] = None):
        super().__init__(master)
        self.session  = session
        self.entry_id = entry_id
        self.saved    = False
        self.title("Edit Entry" if entry_id else "New Entry")
        self.configure(bg=_C["bg"])
        self.resizable(False, False)
        _center(self, 500, 490)
        self.grab_set()
        self._build()
        if entry_id:
            self._load()
        # Every interaction resets the auto-lock timer
        self.bind_all("<Key>",    lambda _: self.session.touch(), "+")
        self.bind_all("<Button>", lambda _: self.session.touch(), "+")

    def _build(self):
        is_edit = bool(self.entry_id)
        tk.Frame(self, bg=_C["accent"], height=2).pack(fill="x")
        tk.Frame(self, height=12, bg=_C["bg"]).pack()
        _lbl(self, "  ✏  EDIT ENTRY" if is_edit else "  ＋  NEW ENTRY",
             font=_FT, color=_C["accent"]).pack(padx=28, anchor="w")
        tk.Frame(self, height=6, bg=_C["bg"]).pack()
        _sep(self).pack(fill="x", padx=28)
        tk.Frame(self, height=10, bg=_C["bg"]).pack()

        f = ttk.Frame(self); f.pack(fill="x", padx=28)
        f.columnconfigure(1, weight=1)

        def _row(r, label, show=False):
            _lbl(f, label, color=_C["fg2"], font=_FS).grid(
                row=r*2, column=0, columnspan=3, sticky="w", pady=(6, 1))
            e = _entry(f, show="●" if show else None, width=34)
            e.grid(row=r*2+1, column=0, columnspan=2, sticky="ew", padx=(0,4))
            return e

        self._name  = _row(0, "NAME / LABEL  *")
        self._url   = _row(1, "URL / WEBSITE")
        self._user  = _row(2, "USERNAME / EMAIL  *")

        # Password row
        _lbl(f, "PASSWORD  *", color=_C["fg2"], font=_FS).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(6, 1))
        self._pass_var  = tk.StringVar()
        self._show_pass = tk.BooleanVar(value=False)
        self._pass_e    = ttk.Entry(f, textvariable=self._pass_var,
                                     show="●", width=26)
        self._pass_e.grid(row=7, column=0, sticky="ew", padx=(0, 4))

        def _toggle():
            self._pass_e.config(show="" if self._show_pass.get() else "●")
        ttk.Checkbutton(f, text="Show", variable=self._show_pass,
                         command=_toggle).grid(row=7, column=1, padx=2)

        _btn(f, "⚡ Generate", self._gen_pw,
             style="Ghost.TButton").grid(row=7, column=2, padx=(4,0))

        self._notes = _row(4, "NOTES")

        self._err = _lbl(self, color=_C["accent2"], font=_FS)
        self._err.pack(padx=28, anchor="w", pady=6)

        bf = ttk.Frame(self); bf.pack(padx=28, pady=10, anchor="w")
        _btn(bf, "  SAVE  ", self._save,
             style="Accent.TButton").pack(side="left", padx=(0, 8))
        _btn(bf, "Cancel", self.destroy).pack(side="left")

    def _gen_pw(self):
        pw = generate_password(20)
        self._pass_var.set(pw)
        self._pass_e.config(show="")
        self._show_pass.set(True)

    def _load(self):
        data = self.session.decrypt(self.entry_id)
        if not data:
            messagebox.showerror("Decryption Error",
                "Could not decrypt entry.\n"
                "The vault may have been tampered with.", parent=self)
            self.destroy(); return
        self._name.insert(0,  data.get("name",     ""))
        self._url.insert(0,   data.get("url",      ""))
        self._user.insert(0,  data.get("username", ""))
        self._pass_var.set(   data.get("password", ""))
        self._notes.insert(0, data.get("notes",    ""))

    def _save(self):
        name  = self._name.get().strip()
        url   = self._url.get().strip()
        user  = self._user.get().strip()
        pw    = self._pass_var.get()
        notes = self._notes.get().strip()

        if not name:
            self._err.config(text="Name is required."); return
        if not user:
            self._err.config(text="Username is required."); return
        if not pw:
            self._err.config(text="Password is required."); return

        self._err.config(text="\u23f3  Saving\u2026")
        self.update_idletasks()

        # B9 FIX: encrypt + write in background thread so main thread never freezes
        entry_id  = self.entry_id   # capture before thread
        session   = self.session

        def _do_save():
            if entry_id:
                session.update(entry_id, name, url, user, pw, notes)
            else:
                session.add(name, url, user, pw, notes)
            zero_bytes(bytearray(pw.encode()))

            def _finish():
                try:
                    self.saved = True
                    self.destroy()
                except Exception:
                    pass
            self.after(0, _finish)

        threading.Thread(target=_do_save, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
#  View / Reveal Dialog
# ─────────────────────────────────────────────────────────────────────────────

class ViewDialog(tk.Toplevel):

    def __init__(self, master: tk.Tk, session: Session,
                 entry_id: str, root_ref: tk.Tk):
        super().__init__(master)
        self.session  = session
        self.entry_id = entry_id
        self.root_ref = root_ref
        self.title("View Entry")
        self.configure(bg=_C["bg"])
        self.resizable(False, False)
        _center(self, 530, 410)
        self.grab_set()
        self._build()
        self.bind_all("<Key>",    lambda _: self.session.touch(), "+")
        self.bind_all("<Button>", lambda _: self.session.touch(), "+")

    def _build(self):
        data = self.session.decrypt(self.entry_id)
        if not data:
            messagebox.showerror("Integrity Error",
                "Decryption failed.\n"
                "This entry may have been tampered with.", parent=self)
            self.destroy(); return

        tk.Frame(self, bg=_C["accent"], height=2).pack(fill="x")
        tk.Frame(self, height=12, bg=_C["bg"]).pack()
        _lbl(self, f"  🔎  {data['name']}",
             font=_FH, color=_C["accent"]).pack(padx=28, anchor="w")
        tk.Frame(self, height=6, bg=_C["bg"]).pack()
        _sep(self).pack(fill="x", padx=28)
        tk.Frame(self, height=10, bg=_C["bg"]).pack()

        c = ttk.Frame(self); c.pack(fill="x", padx=28)
        c.columnconfigure(1, weight=1)

        # BUG-2 FIX: use a plain helper that NEVER mixes text= and textvariable=.
        # For non-password rows use tk.Label with literal text (no StringVar).
        # For the password row use a StringVar + tk.Label (no text= arg at all).
        def _val_label(parent, row, text_value):
            """Static value label — no StringVar, no text/textvariable conflict."""
            lbl = tk.Label(
                parent,
                text=text_value,           # plain string, always renders
                bg=_C["bg"],
                fg=_C["fg"],
                font=_F,
                anchor="w",
            )
            lbl.grid(row=row, column=1, sticky="w", pady=6)
            return lbl

        def _val_var_label(parent, row, sv):
            """Dynamic value label backed by StringVar — NO text= arg passed."""
            lbl = tk.Label(
                parent,
                textvariable=sv,           # ONLY textvariable, never text=
                bg=_C["bg"],
                fg=_C["fg"],
                font=_F,
                anchor="w",
            )
            lbl.grid(row=row, column=1, sticky="w", pady=6)
            return lbl

        # Helper: treat empty string as em-dash so the cell is never blank
        def _v(raw: str) -> str:
            return raw if raw and raw.strip() else "—"

        rows = [
            ("URL",      _v(data.get("url",      "")), True),
            ("USERNAME", _v(data.get("username", "")), True),
            ("PASSWORD", _v(data.get("password", "")), True),
            ("NOTES",    _v(data.get("notes",    "")), False),
        ]

        for r, (label, val, copyable) in enumerate(rows):
            # Column 0: field label
            tk.Label(c, text=label, bg=_C["bg"], fg=_C["fg2"],
                     font=_FS, anchor="w", width=10).grid(
                row=r, column=0, sticky="w", pady=6, padx=(0, 14))

            col = 2
            if label == "PASSWORD":
                # Use StringVar so Reveal toggle can switch between ● and value
                sv = tk.StringVar(value="●●●●●●●●")
                _val_var_label(c, r, sv)

                def _tog(sv=sv, v=val, st=[True]):
                    st[0] = not st[0]
                    sv.set("●●●●●●●●" if st[0] else v)
                _btn(c, "Reveal", _tog,
                     style="Ghost.TButton").grid(row=r, column=col, padx=3)
                col += 1
            else:
                # Non-secret rows: static tk.Label — immune to text/textvariable bug
                _val_label(c, r, val)

            if copyable:
                v = val
                def _copy(text=v, lbl=label):
                    self.session.copy_to_clipboard(self.root_ref, text)
                    # Toast runs on main thread — safe
                    _toast(self.root_ref,
                           f"{lbl} copied \u2014 clears in {CLIPBOARD_CLEAR_SEC}s")
                _btn(c, "Copy", _copy,
                     style="Ghost.TButton").grid(row=r, column=col, padx=3)

        tk.Frame(self, height=6, bg=_C["bg"]).pack()
        _sep(self).pack(fill="x", padx=28)
        _lbl(self,
             f"⏱  Clipboard clears after {CLIPBOARD_CLEAR_SEC}s  ·  "
             f"Auto-lock in {AUTO_LOCK_SEC // 60} min idle",
             color=_C["fg2"], font=_FS).pack(padx=28, anchor="w", pady=8)
        _btn(self, "  Close  ", self.destroy,
             style="Ghost.TButton").pack(padx=28, anchor="w")


# ─────────────────────────────────────────────────────────────────────────────
#  Main Vault Window
# ─────────────────────────────────────────────────────────────────────────────

class VaultWindow(ttk.Frame):

    def __init__(self, master: tk.Tk, session: Session):
        super().__init__(master)
        self.master   = master
        self.session  = session
        # entry_id → plaintext password (only for currently-revealed rows)
        self._revealed: dict  = {}
        self._decrypting: set = set()   # B6 FIX: IDs currently being decrypted
        # FIX-4: Wire auto-lock callback so vault relocks the UI
        self.session._on_auto_lock_cb = self._on_auto_lock
        self.pack(fill="both", expand=True)
        self._build_header()
        self._build_toolbar()
        self._build_search()
        self._build_table()
        self._build_footer()
        self.refresh()
        self.bind_all("<Key>",    lambda _: self.session.touch(), "+")
        self.bind_all("<Button>", lambda _: self.session.touch(), "+")

    def _build_header(self):
        hdr = tk.Frame(self, bg=_C["panel"]); hdr.pack(fill="x")
        tk.Frame(hdr, bg=_C["accent"], height=2).pack(fill="x")
        inner = tk.Frame(hdr, bg=_C["panel"])
        inner.pack(fill="x", padx=16, pady=10)
        _lbl(inner, "⬡  VAULT", font=_FT, color=_C["accent"]).pack(side="left")
        for text, cmd, sty in [
            ("🔒 LOCK", self._lock, "Ghost.TButton"),
            ("✕",       self._safe_quit, "Danger.TButton"),
        ]:
            _btn(inner, text, cmd, style=sty).pack(side="right", padx=3)

    def _build_toolbar(self):
        tb = tk.Frame(self, bg=_C["bg"]); tb.pack(fill="x", padx=14, pady=(6,2))
        for text, cmd, sty in [
            ("  ＋  ADD",     self._add,    "Accent.TButton"),
            ("  ✏  EDIT",    self._edit,   "Ghost.TButton"),
            ("  🔎  VIEW",   self._view,   "Ghost.TButton"),
            ("  🗑  DELETE", self._delete, "Danger.TButton"),
        ]:
            _btn(tb, text, cmd, style=sty).pack(side="left", padx=(0, 4))

    def _build_search(self):
        sf = tk.Frame(self, bg=_C["bg"]); sf.pack(fill="x", padx=14, pady=4)
        _lbl(sf, "SEARCH:", color=_C["fg2"], font=_FS).pack(side="left", padx=(0,8))
        self._q = tk.StringVar()
        self._q.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(sf, textvariable=self._q, width=40).pack(side="left")
        _lbl(sf, "  name & URL only  ·  passwords stay encrypted",
             color=_C["fg2"], font=_FS).pack(side="left", padx=8)

    def _build_table(self):
        outer = tk.Frame(self, bg=_C["border"])
        outer.pack(fill="both", expand=True, padx=14, pady=6)
        cols = ("Name / Label", "URL / Website", "Password", "Modified")
        self._tree = ttk.Treeview(outer, columns=cols, show="headings",
                                   selectmode="browse")
        for col, w in zip(cols, (185, 195, 210, 130)):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="w", stretch=True)

        # Cyan bold text for rows whose password is revealed
        self._tree.tag_configure("revealed",
            foreground=_C["accent"],
            font=("Consolas", 10, "bold"))

        vsb = ttk.Scrollbar(outer, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(side="left", fill="both", expand=True)

        # Double-click → full ViewDialog (copy / notes)
        self._tree.bind("<Double-1>", lambda _: self._open_dialog())
        self._tree.bind("<Return>",   lambda _: self._open_dialog())
        self._tree.bind("<Delete>",   lambda _: self._delete())

    def _build_footer(self):
        ft = tk.Frame(self, bg=_C["panel"]); ft.pack(fill="x")
        tk.Frame(ft, bg=_C["border"], height=1).pack(fill="x")
        inner = tk.Frame(ft, bg=_C["panel"])
        inner.pack(fill="x", padx=16, pady=4)
        self._fv = tk.StringVar()
        # B3 FIX: tk.Label (not ttk) so textvariable always wins — ttk ignores
        # textvariable when text='' is also passed (clam theme bug).
        tk.Label(inner, textvariable=self._fv,
                 bg=_C["panel"], fg=_C["fg2"],
                 font=_FS).pack(side="left")
        tk.Label(inner,
                 text=f"Clipboard: {CLIPBOARD_CLEAR_SEC}s  \u00b7  "
                      f"Auto-lock: {AUTO_LOCK_SEC // 60} min  \u00b7  "
                      f"Vault: {VAULT_FILE.name}",
                 bg=_C["panel"], fg=_C["fg2"],
                 font=_FS).pack(side="right")

    def refresh(self):
        q   = self._q.get().lower().strip() if hasattr(self, "_q") else ""
        self._tree.delete(*self._tree.get_children())
        all_e = storage_list_entries()
        shown = 0
        for e in all_e:
            if q and q not in e["name"].lower() \
               and q not in e.get("url", "").lower():
                continue
            mod = time.strftime("%Y-%m-%d %H:%M",
                                 time.localtime(e.get("modified_at", 0)))
            eid = e["id"]
            if eid in self._revealed:
                pw_cell = self._revealed[eid]
                tag     = ("revealed",)
            else:
                pw_cell = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
                tag     = ()
            self._tree.insert("", "end", iid=eid,
                values=(e["name"], e.get("url",""), pw_cell, mod),
                tags=tag)
            shown += 1
        total = len(all_e)
        hint  = f"  \u00b7  {len(self._revealed)} revealed" if self._revealed else ""
        self._fv.set(
            f"{shown} of {total} entr{'y' if total==1 else 'ies'}"
            + (f"  \u00b7  Filter: \"{q}\"" if q else "")
            + hint
        )

    def _sel(self) -> Optional[str]:
        s = self._tree.selection(); return s[0] if s else None

    def _need_sel(self, action: str) -> Optional[str]:
        eid = self._sel()
        if not eid:
            messagebox.showinfo("No Selection",
                f"Please select an entry to {action}.", parent=self.master)
        return eid

    def _add(self):
        d = EntryDialog(self.master, self.session)
        self.master.wait_window(d)
        if d.saved: self.refresh()

    def _edit(self):
        eid = self._need_sel("edit")
        if not eid: return
        d = EntryDialog(self.master, self.session, entry_id=eid)
        self.master.wait_window(d)
        if d.saved: self.refresh()

    def _view(self):
        """
        VIEW button — toggles password visible/hidden inline in the table row.
        Decrypt runs in a background thread so the UI never freezes.
        Second click hides and zeroes the stored plaintext.
        """
        eid = self._need_sel("reveal/hide")
        if not eid:
            return

        if eid in self._revealed:
            # Already revealed — hide and zero
            pw_plain = self._revealed.pop(eid)
            zero_bytes(bytearray(pw_plain.encode("utf-8")))
            self.refresh()
            _toast(self.master, "Password hidden")
            return

        # B6 FIX: ignore rapid double-clicks while a decrypt is in progress
        if eid in self._decrypting:
            return
        self._decrypting.add(eid)

        def _do_decrypt():
            data = self.session.decrypt(eid)
            def _done():
                self._decrypting.discard(eid)
                if not data:
                    _toast(self.master, "Decryption failed")
                    return
                pw = data.get("password", "")
                self._revealed[eid] = pw
                self.refresh()
                _toast(self.master, "Password shown \u2014 click VIEW to hide")
            self.master.after(0, _done)

        threading.Thread(target=_do_decrypt, daemon=True).start()

    def _open_dialog(self):
        """Double-click / Enter — open full ViewDialog (copy, notes, reveal)."""
        eid = self._need_sel("view")
        if not eid: return
        ViewDialog(self.master, self.session, eid, self.master)

    def _delete(self):
        eid = self._need_sel("delete")
        if not eid: return
        name = self._tree.item(eid)["values"][0]
        if messagebox.askyesno(
            "Confirm Deletion",
            f"Permanently delete  '{name}'?\nThis cannot be undone.",
            icon="warning", parent=self.master):
            self.session.delete(eid)
            self.refresh()

    def _lock(self):
        self._zero_revealed()
        self.session.logout()
        self.destroy()
        _show_lock_screen(self.master)

    def _safe_quit(self):
        self._zero_revealed()
        self.session.logout()
        self.master.destroy()

    def _zero_revealed(self):
        """Zero all in-memory revealed passwords before locking."""
        for pw in self._revealed.values():
            zero_bytes(bytearray(pw.encode("utf-8")))
        self._revealed.clear()

    def _on_auto_lock(self):
        """FIX-4: Called by idle timer from background thread → marshal to UI."""
        try:
            self.master.after(0, self._do_auto_lock)
        except Exception:
            pass

    def _do_auto_lock(self):
        self._zero_revealed()
        try:
            self.destroy()
        except Exception:
            pass
        messagebox.showinfo(
            "Auto-Locked",
            f"Vault locked after {AUTO_LOCK_SEC // 60} minutes of inactivity.",
            parent=self.master)
        _show_lock_screen(self.master)


# ─────────────────────────────────────────────────────────────────────────────
#  Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def _show_lock_screen(root: tk.Tk) -> None:
    session = Session()
    dlg     = LockScreen(root, session)
    root.wait_window(dlg)
    if not session.active:
        root.destroy()
        return
    VaultWindow(root, session)


def main() -> None:
    root = tk.Tk()
    root.title("\u2b21  Secure Password Manager  v6.0")
    root.configure(bg=_C["bg"])
    root.minsize(740, 460)
    _center(root, 820, 560)
    _apply_theme(root)

    def _on_close():
        for w in root.winfo_children():
            if isinstance(w, VaultWindow):
                w._zero_revealed()   # B2 FIX: zero plaintext before exit
                w.session.logout()
                break
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)

    if not vault_exists():
        setup = SetupDialog(root)
        root.wait_window(setup)
        if not setup.result:
            root.destroy()
            return
        messagebox.showinfo(
            "Vault Initialized",
            f"Vault created at:\n{VAULT_FILE}\n\n"
            "Please enter your master password to unlock it.",
            parent=root)

    _show_lock_screen(root)
    root.mainloop()


if __name__ == "__main__":
    main()
