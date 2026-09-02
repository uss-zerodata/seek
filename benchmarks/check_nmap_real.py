"""Dev check: parse the real scans in the workspace `nmap/` folder.

Not a committed test - it needs scan data that is deliberately gitignored. Run
it after touching `seek.nmap.parse` to confirm the parser still agrees with real
nmap output rather than only with the synthetic fixtures:

    uv run python benchmarks/check_nmap_real.py

Expected for `nmap_tcp_top1000_*.xml` (scanned with -Pn):
    256 hosts, 40 ports, 90 scripts (55 structured), 255 asserted up, 9 with evidence
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from seek.nmap.parse import NmapParseError, parse_file

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "nmap")


def main() -> int:
    files = sorted(ROOT.rglob("*.xml"))
    if not files:
        print(f"no scans under {ROOT}/ - nothing to check", file=sys.stderr)
        return 1
    for path in files:
        t0 = time.perf_counter()
        try:
            sf = parse_file(path)
        except NmapParseError as exc:
            print(f"{path.name:<44} FAILED  {exc}")
            continue
        dt = (time.perf_counter() - t0) * 1000
        scripts = [s for h in sf.hosts for x in (h.services, [h]) for o in x
                   for s in getattr(o, "scripts", [])]
        print(
            f"{path.name:<44} {dt:6.0f} ms  hosts={len(sf.hosts):<4} "
            f"ports={sum(len(h.services) for h in sf.hosts):<4} "
            f"scripts={len(scripts):<4} structured={sum(1 for s in scripts if s.data):<4} "
            f"-Pn={sf.disabled_ping!s:<5} "
            f"asserted_up={sum(1 for h in sf.hosts if h.state == 'up'):<4} "
            f"evidenced={sum(1 for h in sf.hosts if h.reachable)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
