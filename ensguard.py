#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ensguard — generate & score look-alike variants of ENS labels/crypto handles.

Offline features:
  - Variants via Unicode confusables (Latin/Cyrillic/Greek look-alikes)
  - Typos: single-key neighbors, omission, duplication, adjacent swap
  - Risk scoring: visual confusability + edit distance + pattern severity
  - Exports: JSON / CSV / TXT
  - SVG badge generator for quick warnings

Examples:
  $ python ensguard.py generate vitalik --max 150 --csv out.csv
  $ python ensguard.py generate mydao --json out.json --txt watchlist.txt
  $ python ensguard.py svg-badge vitalik --out vitalik-lookalikes.svg
"""

import csv
import json
import math
import os
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

import click
import idna  # for punycode rendering (IDNA/UTS-46 conformity)

# ------------------ Confusables & keyboard neighbors ------------------

# Minimal curated confusable map for lowercase ASCII-focused labels.
# We prefer a small, high-signal set over exhaustive (and noisy) tables.
CONFUSABLES: Dict[str, List[str]] = {
    "a": ["\u0430"],  # Cyrillic a
    "c": ["\u0441"],  # Cyrillic es
    "e": ["\u0435"],  # Cyrillic ie
    "i": ["\u0456"],  # Cyrillic i
    "j": ["\u0458"],  # Cyrillic je
    "o": ["\u043e", "\u03bf"],  # Cyrillic o, Greek omicron
    "p": ["\u0440"],  # Cyrillic er
    "s": ["\u0455"],  # Cyrillic dze (looks like s)
    "x": ["\u0445", "\u03c7"],  # Cyrillic ha, Greek chi
    "y": ["\u0443"],  # Cyrillic u (looks like y in Latin)
    "h": ["\u043d"],  # Cyrillic en
    "k": ["\u043a"],  # Cyrillic ka
    "m": ["\u043c"],  # Cyrillic em
    "t": ["\u0442"],  # Cyrillic te
    "b": ["\u0463"],  # Cyrillic yat (approx)
    "g": ["\u0261"],  # Latin small script g
    "l": ["\u04cf", "\u0131"],  # Cyrillic palochka, Latin dotless i
    "u": ["\u044e"],  # Cyrillic yu (loose)
    "n": ["\u0578"],  # Armenian o (visually n/o-ish for some fonts)
    "v": ["\u03bd"],  # Greek nu
    "r": ["\u0433"],  # Cyrillic ge (loose)
    "w": ["\u051d"],  # Cyrillic we
    "f": ["\u017f"],  # Long s (historical), looks f-ish in some fonts
    "q": ["\u051b"],  # Cyrillic qa
    "z": ["\u01b6"],  # z with stroke
    "d": ["\u0501"],  # Cyrillic komi dze
    "0": ["o", "\u043e"],  # zero vs o
    "1": ["l", "i", "\u04cf", "\u0131"],
    "3": ["\u0437"],  # Cyrillic ze looks like 3
    "5": ["\u0455"],  # looks like s
}

# Simple US QWERTY neighbor graph for typo simulation (lowercase).
KEY_NEIGHBORS: Dict[str, str] = {
    "q":"was", "w":"qesad", "e":"wsrdf", "r":"edft", "t":"rfgy", "y":"tghu", "u":"yjhki", "i":"ujklo",
    "o":"iklp", "p":"ol", "a":"qwsz", "s":"qweadzx", "d":"wersfxc", "f":"ertdgcv", "g":"rtyfhvb",
    "h":"tyugjbn", "j":"yuihknm", "k":"uiojm", "l":"opk", "z":"asx", "x":"zsdc", "c":"xdfv", "v":"cfgb",
    "b":"vghn", "n":"bhjm", "m":"njk"
}

# ------------------ Data structures ------------------

@dataclass
class Variant:
    variant: str
    kind: str             # 'confusable', 'neighbor', 'omit', 'dup', 'swap'
    distance: int         # Levenshtein distance to base
    visual_score: float   # 0..1 (1 = extremely confusable)
    punycode: str         # ascii-compatible IDNA (xn--...)
    note: str             # brief reason/context

# ------------------ Helpers ------------------

def normalize_label(label: str) -> str:
    # ENS labels are lowercase, hyphen allowed, digits allowed.
    return label.strip().lower()

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0: return len(b)
    if len(b) == 0: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = prev[j] + 1
            dele = curr[j-1] + 1
            sub = prev[j-1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]

def puny(label: str) -> str:
    # "vitalik" => "vitalik", "vіtalik" => "xn--..."
    try:
        return idna.encode(label).decode("ascii")
    except Exception:
        return "<invalid-idna>"

def visual_confusability(base: str, var: str) -> float:
    """
    Heuristic:
      - Start at 0.0; +0.5 if lengths equal, +0.2 if only confusables used, +0.2 if edit distance ≤ 1,
        +0.1 if punctuation/layout identical. Clamp to 1.0.
    """
    score = 0.0
    if len(base) == len(var):
        score += 0.5
    if all((c == v) or (c in CONFUSABLES and v in CONFUSABLES[c]) for c, v in zip(base, var)) and len(base)==len(var):
        score += 0.2
    if levenshtein(base, var) <= 1:
        score += 0.2
    # Lightweight punctuation/layout check
    def layout(s: str): return "".join("-" if ch=="-" else "a" if ch.isalpha() else "d" if ch.isdigit() else "?")
    if layout(base) == layout(var):
        score += 0.1
    return min(1.0, score)

def uniq(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

# ------------------ Variant generators ------------------

def gen_confusables(base: str, max_per_letter: int = 2) -> Set[str]:
    out: Set[str] = set()
    chars = list(base)
    for i, ch in enumerate(chars):
        reps = CONFUSABLES.get(ch, [])[:max_per_letter]
        for r in reps:
            alt = chars.copy()
            alt[i] = r
            out.add("".join(alt))
    # two-position replacements (combinatorial but capped)
    for i, ch1 in enumerate(chars):
        r1s = CONFUSABLES.get(ch1, [])[:1]
        for j in range(i+1, len(chars)):
            ch2 = chars[j]
            r2s = CONFUSABLES.get(ch2, [])[:1]
            for r1 in r1s:
                for r2 in r2s:
                    alt = chars.copy()
                    alt[i], alt[j] = r1, r2
                    out.add("".join(alt))
    return out

def gen_neighbors(base: str) -> Set[str]:
    out: Set[str] = set()
    for i, ch in enumerate(base):
        nbs = KEY_NEIGHBORS.get(ch, "")
        for n in nbs:
            out.add(base[:i] + n + base[i+1:])
    return out

def gen_omissions(base: str) -> Set[str]:
    out = set()
    for i in range(len(base)):
        out.add(base[:i] + base[i+1:])
    return out

def gen_duplications(base: str) -> Set[str]:
    out = set()
    for i in range(len(base)):
        out.add(base[:i] + base[i] + base[i:] )
    return out

def gen_swaps(base: str) -> Set[str]:
    out = set()
    for i in range(len(base)-1):
        out.add(base[:i] + base[i+1] + base[i] + base[i+2:])
    return out

def build_variants(label: str, cap: int = 300) -> List[Variant]:
    base = normalize_label(label)

    candidates: List[Tuple[str, str, str]] = []  # (variant, kind, note)

    for v in gen_confusables(base):
        candidates.append((v, "confusable", "unicode look-alike"))
    for v in gen_neighbors(base):
        candidates.append((v, "neighbor", "keyboard neighbor"))
    for v in gen_omissions(base):
        candidates.append((v, "omit", "omission"))
    for v in gen_duplications(base):
        candidates.append((v, "dup", "duplication"))
    for v in gen_swaps(base):
        candidates.append((v, "swap", "adjacent swap"))

    # de-dup and drop exact self
    seen: Set[str] = set()
    uniqed: List[Tuple[str, str, str]] = []
    for v, kind, note in candidates:
        if v == base: 
            continue
        if v not in seen:
            seen.add(v)
            uniqed.append((v, kind, note))

    # Score and sort
    scored: List[Variant] = []
    for v, kind, note in uniqed:
        dist = levenshtein(base, v)
        vis = visual_confusability(base, v)
        scored.append(Variant(
            variant=v, kind=kind, distance=dist, visual_score=vis, punycode=puny(v), note=note
        ))

    # Rank: higher visual_score, then smaller distance, then confusable > others, then length gap
    kind_rank = {"confusable":0, "neighbor":1, "swap":2, "dup":3, "omit":4}
    scored.sort(key=lambda x: (
        -(x.visual_score),
        x.distance,
        kind_rank.get(x.kind, 9),
        abs(len(x.variant) - len(base))
    ))

    return scored[:cap]

# ------------------ CLI ------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """ensguard — ENS look-alike generator & risk scorer (offline)."""
    pass

@cli.command("generate")
@click.argument("label", type=str)
@click.option("--max", "cap", type=int, default=200, show_default=True,
              help="Maximum variants to output after scoring.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON output to file.")
@click.option("--csv", "csv_out", type=click.Path(writable=True), default=None, help="Write CSV output to file.")
@click.option("--txt", "txt_out", type=click.Path(writable=True), default=None, help="Write plain-text watchlist.")
def generate_cmd(label: str, cap: int, json_out: Optional[str], csv_out: Optional[str], txt_out: Optional[str]):
    """Generate ranked look-alike variants for LABEL."""
    variants = build_variants(label, cap=cap)
    data = [asdict(v) for v in variants]

    # Console preview (top 10)
    preview = [{k: d[k] for k in ("variant","kind","visual_score","distance","punycode")} for d in data[:10]]
    click.echo(json.dumps(preview, indent=2, ensure_ascii=False))

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        click.echo(f"JSON written: {json_out}")

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["variant","kind","distance","visual_score","punycode","note"])
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        click.echo(f"CSV written: {csv_out}")

    if txt_out:
        with open(txt_out, "w", encoding="utf-8") as f:
            for d in data:
                f.write(d["variant"] + "\n")
        click.echo(f"TXT watchlist written: {txt_out}")

@cli.command("svg-badge")
@click.argument("label", type=str)
@click.option("--out", type=click.Path(writable=True), default="ensguard-badge.svg", show_default=True)
def svg_badge_cmd(label: str, out: str):
    """Emit a small SVG badge advertising that look-alikes are monitored."""
    l = normalize_label(label)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="420" height="48" role="img" aria-label="Look-alike protection">
  <rect width="420" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    {l}.eth look-alike protection by ensguard
  </text>
  <circle cx="395" cy="24" r="6" fill="#3fb950"/>
</svg>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    click.echo(f"SVG badge written: {out}")

@cli.command("explain")
@click.argument("label", type=str)
def explain_cmd(label: str):
    """Explain how ensguard scores and what to watch for."""
    l = normalize_label(label)
    msg = {
        "label": l,
        "scoring": {
            "visual_score": "0..1, higher is more confusable (same length + confusables + edit distance ≤1).",
            "distance": "Levenshtein distance to the base label.",
            "kinds": {
                "confusable": "Unicode look-alike characters swapped in.",
                "neighbor": "Single-key keyboard neighbor typo.",
                "omit": "One-character omission.",
                "dup": "Duplicate a character.",
                "swap": "Swap adjacent characters."
            }
        },
        "advice": [
            "Register the top 3–10 variants with the highest visual_score if they matter to your brand.",
            "Publish a watchlist (TXT/CSV) and alert on any resolution or listings matching it.",
            "Consider using an ENS contenthash to point variants to a warning page."
        ]
    }
    click.echo(json.dumps(msg, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    cli()
