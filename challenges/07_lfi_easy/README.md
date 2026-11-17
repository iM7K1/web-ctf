# 07 — Path Traversal · Easy · 100 pts

**Course ref:** Lab4 LFI & Directory Traversal.

## Scenario
A document portal serves `/download?file=report.txt` from `www/files/`. The flag is in `secret/flag.txt`, two levels up.

```
07_lfi_easy/
  www/files/report.txt   <- base folder
  secret/flag.txt        <- target
```

## Walkthrough
```
/download?file=../../secret/flag.txt
```
(If you use curl, add `--path-as-is`. Browsers keep `../` inside the query string.) Flag: `FLAG{path_traversal_dotdot}`

The lab sandbox confines reads to this challenge folder, so `/etc/passwd` is refused on purpose.

## The bug
`os.path.join(FILES_DIR, name)` with no containment check (`# ======= VULN HERE =======`).

## The fix
```python
base = os.path.realpath(FILES_DIR)
real = os.path.realpath(os.path.join(base, name))
if not real.startswith(base + os.sep):
    return 403
```
Better still, map IDs to files (`?id=3`) instead of accepting file names.
