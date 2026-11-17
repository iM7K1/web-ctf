# 08 — LFI: Traversal with Filter Bypass · Hard · 250 pts

**Course ref:** Lab4 LFI, Ch07 Filter Evasion (encoding, nested sequences).

## Scenario
The same portal, "patched". The page shows what your input became after the filter. The filter removes `../` **once**, and it runs on the raw parameter **before** URL-decoding.

## Walkthrough
- `../../secret/flag.txt` becomes `secret/flag.txt` after the filter: not found.
- **Nested:** `....//....//secret/flag.txt`. Removing the inner `../` from each `....//` leaves `../`.
- **Encoded:** `..%2f..%2fsecret%2fflag.txt`. The filter doesn't see `../`, and decoding afterwards rebuilds it.

Flag: `FLAG{lfi_encoded_traversal_bypass}`

## The bug
`filtered = raw.replace("../", "")` runs once, on still-encoded input (`# ======= VULN HERE =======`).

## The fix
Never "clean" paths with string replacement. Decode fully, canonicalise with `realpath`, then check containment (as in challenge 07), and reject the request if the path leaves the base folder.
