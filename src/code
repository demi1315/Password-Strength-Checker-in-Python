
"""
password_checker_cli.py

CLI Password Strength Checker:
 - Regex rules (length, uppercase, lowercase, digits, symbols)
 - zxcvbn scoring + feedback
 - Local weak/banned wordlist checks
 - Batch mode (file of passwords)
 - JSON export of results
 - Secure prompt when password not provided on CLI

Usage examples:
  # interactive prompt
  python password_checker_cli.py

  # single password via argument (less secure - appears in shell history)
  python password_checker_cli.py --password "P@ssw0rd123!"

  # batch mode (one password per line)
  python password_checker_cli.py --file passwords.txt --export results.json

  # tune attacker guesses/sec used in time estimation
  python password_checker_cli.py --password "hunter2" --gps 1e9
"""

from __future__ import annotations
import argparse
import json
import logging
import math
import getpass
from pathlib import Path
from typing import Dict, Any, List, Optional

import re
from functools import lru_cache
from zxcvbn import zxcvbn

# ---------- Configuration ----------
DEFAULT_MIN_LENGTH = 12
DEFAULT_WEAK_WORDLIST = Path("./weak_passwords.txt")
DEFAULT_BANNED_WORDLIST = Path("./banned_passwords.txt")

logging.basicConfig(level=logging.INFO, filename="password_checker_cli.log",
                    format="%(asctime)s - %(levelname)s - %(message)s")

# ---------- Utilities ----------


def load_wordlist(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip()]


@lru_cache(maxsize=2048)
def regex_checks(password: str, min_length: int = DEFAULT_MIN_LENGTH) -> Dict[str, bool]:
    """Return dict with boolean results for each regex check."""
    return {
        "min_length": len(password) >= min_length,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_symbol": bool(re.search(r"[^\w\s]", password)),
    }


def _seconds_to_human(seconds: float) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    minute = 60
    hour = 3600
    day = 86400
    year = 31536000
    if seconds < minute:
        return f"{seconds:.2f} seconds"
    if seconds < hour:
        return f"{seconds/60:.2f} minutes"
    if seconds < day:
        return f"{seconds/3600:.2f} hours"
    if seconds < year:
        return f"{seconds/day:.2f} days"
    return f"{seconds/year:.2f} years"


def estimate_crack_time(zx_result: Dict[str, Any], guesses_per_sec: float) -> Optional[float]:
    """
    Estimate seconds to crack based on zxcvbn output.
    Uses zx_result['guesses'] if present; otherwise attempts to compute from 'entropy'.
    We assume average attacker needs half the keyspace (guesses/2) so seconds = (guesses/2)/gps
    """
    guesses = zx_result.get("guesses")
    if guesses is None:
        log10 = zx_result.get("guesses_log10")
        if log10 is not None:
            try:
                guesses = 10 ** float(log10)
            except Exception:
                guesses = None
    if guesses is None:
        entropy = zx_result.get("entropy")
        if entropy is not None:
            guesses = 2 ** float(entropy)
    if guesses is None or guesses <= 0 or guesses_per_sec <= 0:
        return None
    seconds = (guesses / 2) / float(guesses_per_sec)
    return seconds


# ---------- Core analysis ----------


def analyze_password(password: str, weak_words: List[str], banned_words: List[str],
                     min_length: int, guesses_per_sec: float) -> Dict[str, Any]:
    """Analyze a single password and return a dict with results."""
    if password is None:
        raise ValueError("password cannot be None")

    pw_clean = password.strip()
    regex_result = regex_checks(pw_clean, min_length)

    in_weak = pw_clean in weak_words
    in_banned = pw_clean in banned_words

    zx = zxcvbn(pw_clean)  # returns a dict with keys: score, feedback, guesses, etc.
    score = int(zx.get("score", 0))
    feedback = zx.get("feedback", {}) or {}
    suggestions = feedback.get("suggestions", [])
    warning = feedback.get("warning", "")

    missing = [k for k, ok in regex_result.items() if not ok]

    crack_seconds = estimate_crack_time(zx, guesses_per_sec)
    crack_human = _seconds_to_human(crack_seconds) if crack_seconds is not None else "unknown"

    result = {
        "password": pw_clean,
        "score": score,  # 0..4
        "zxcvbn_guesses": zx.get("guesses"),
        "zxcvbn_guesses_log10": zx.get("guesses_log10"),
        "entropy": zx.get("entropy"),
        "warning": warning,
        "suggestions": suggestions,
        "regex": regex_result,
        "missing_requirements": missing,
        "in_weak_wordlist": in_weak,
        "in_banned_wordlist": in_banned,
        "estimated_crack_time_seconds": crack_seconds,
        "estimated_crack_time_human": crack_human,
    }

    return result


# ---------- CLI handling ----------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CLI Password Strength Checker (zxcvbn + regex + wordlists)")
    input_group = p.add_mutually_exclusive_group()
    input_group.add_argument("--password", "-p", help="Password to check (insecure: appears in shell history)")
    input_group.add_argument("--file", "-f", type=Path, help="File with one password per line to analyze (batch mode)")

    p.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH, help=f"Minimum required length (default {DEFAULT_MIN_LENGTH})")
    p.add_argument("--weak-list", type=Path, default=DEFAULT_WEAK_WORDLIST, help="Path to weak/common passwords file")
    p.add_argument("--banned-list", type=Path, default=DEFAULT_BANNED_WORDLIST, help="Path to banned passwords file")
    p.add_argument("--gps", type=float, default=1e6, help="Guesses per second assumed for attacker (default 1e6)")
    p.add_argument("--export", type=Path, help="Export JSON results to .json file")
    p.add_argument("--quiet", action="store_true", help="Suppress console printing; useful when exporting")
    return p.parse_args()


def main():
    args = parse_args()

    weak_words = load_wordlist(args.weak_list)
    banned_words = load_wordlist(args.banned_list)

    to_analyze: List[str] = []

    if args.password:
        to_analyze = [args.password]
    elif args.file:
        if not args.file.exists():
            print(f"Error: file not found: {args.file}")
            return
        with args.file.open("r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    to_analyze.append(ln)
    else:
        try:
            pw = getpass.getpass("Enter password to analyze (input hidden): ")
        except (KeyboardInterrupt, EOFError):
            print("\nInput cancelled.")
            return
        if not pw:
            print("No password entered; exiting.")
            return
        to_analyze = [pw]

    results = []
    for pw in to_analyze:
        try:
            r = analyze_password(pw, weak_words, banned_words, args.min_length, args.gps)
            results.append(r)
            if not args.quiet:
                print("========================================")
                print(f"Password (masked): {'*' * min(8, len(r['password']))}  (len={len(r['password'])})")
                print(f"zxcvbn score: {r['score']}/4")
                if r['warning']:
                    print(f"Warning: {r['warning']}")
                if r['suggestions']:
                    print("Suggestions:")
                    for s in r['suggestions']:
                        print(f" - {s}")
                if r['missing_requirements']:
                    print("Missing (regex requirements):", ", ".join(r['missing_requirements']))
                print(f"In weak wordlist: {r['in_weak_wordlist']}; In banned list: {r['in_banned_wordlist']}")
                print(f"Estimated crack time (attacker {args.gps:.0f} gps): {r['estimated_crack_time_human']}")
        except Exception as e:
            logging.exception("Error analyzing password")
            print(f"Error analyzing password: {e}")

    if args.export:
        try:
            with args.export.open("w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
            print(f"\nResults exported to {args.export}")
        except Exception as e:
            print(f"Failed to export results: {e}")


if __name__ == "__main__":
    main()
