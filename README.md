# ensguard — defend your ENS from look-alikes

**ensguard** is an offline CLI that generates and **ranks** high-risk look-alike variants of an ENS
label (or any crypto handle). It models Unicode confusables (Latin/Cyrillic/Greek), single-key
neighbor typos, omissions, duplications, and adjacent swaps — then sorts by a visual confusability
score so you can pre-register, watchlist, or warn your users.

No RPC. No internet. Just paste a label and export the results.

## Why this matters

Attackers routinely register look-alike names to impersonate projects and individuals (e.g., using
Cyrillic “а” in place of Latin “a”, or `vitalilk` vs `vitalik`). **ensguard** helps you *preempt*
those registrations by enumerating high-risk variants and ranking them by how likely they are to fool
a human reader.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
