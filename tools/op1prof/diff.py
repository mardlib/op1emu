"""Two runs side by side: what changed in the guest work they counted
(census) and in the code they compiled (compile), so a comparison says
where a difference lies, not only that there is one."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import census, compilation, exits, service, trace
from .marks import Mark, parse_marks, workload_diff

SCHEMA = "op1prof.diff.v1"


def _marks(run: Path) -> List[Mark]:
    log = run / "log.txt"
    if not log.is_file():
        raise ValueError(f"{run}: no log.txt; pass a run/ directory")
    return parse_marks(log.read_text(errors="replace").splitlines())


def first_difference(a: List[Mark], b: List[Mark]) -> Optional[dict]:
    """The first mark at which the two runs' guest work differs, in firing
    order: the phase ending there is where they first did different work."""
    b_by = {m.name: m for m in b}
    previous = "start"
    for mark in a:
        other = b_by.get(mark.name)
        if other is None:
            return {"mark": mark.name, "after": previous, "lines": [f"{mark.name} did not fire in B"]}
        lines = workload_diff([mark], [other])
        if lines:
            return {"mark": mark.name, "after": previous, "lines": lines}
        previous = mark.name
    extra = [m.name for m in b if m.name not in {x.name for x in a}]
    return {"mark": extra[0], "after": previous, "lines": [f"{extra[0]} did not fire in A"]} if extra else None


def _delta_rows(a: Dict[int, Tuple[int, int]], b: Dict[int, Tuple[int, int]]) -> List[dict]:
    rows = []
    for key in set(a) | set(b):
        (ra, pa), (rb, pb) = a.get(key, (0, 0)), b.get(key, (0, 0))
        if (ra, pa) != (rb, pb):
            rows.append({"key": key, "a": [ra, pa], "b": [rb, pb], "delta": [rb - ra, pb - pa],
                         "only": "a" if key not in b else "b" if key not in a else None})
    return rows


def census_diff(run_a: Path, run_b: Path, begin: str, end: str) -> dict:
    """Per-block runs and packets, per-MMR accesses, and, when both runs
    have them, the service and exit censuses, between two marks of two
    census runs."""
    prefix_a, prefix_b = run_a / "census", run_b / "census"
    blocks = _delta_rows(census.phase(prefix_a, "pc", begin, end), census.phase(prefix_b, "pc", begin, end))
    mmio = _delta_rows(census.phase(prefix_a, "mmio", begin, end), census.phase(prefix_b, "mmio", begin, end))
    totals = {}
    for name, kind in (("blocks", "pc"), ("mmio", "mmio")):
        sa, sb = (census.phase(p, kind, begin, end) for p in (prefix_a, prefix_b))
        totals[name] = {"a": [sum(v[i] for v in sa.values()) for i in (0, 1)],
                        "b": [sum(v[i] for v in sb.values()) for i in (0, 1)]}
    out = {"schema": SCHEMA, "kind": "census", "phase": [begin, end], "a": str(run_a), "b": str(run_b),
           "first_difference": first_difference(_marks(run_a), _marks(run_b)),
           "totals": totals, "blocks": blocks, "mmio": mmio}
    if all(Path(f"{p}.service.{m}").is_file() for p in (prefix_a, prefix_b) for m in (begin, end)):
        sa, sb = service.phase(prefix_a, begin, end), service.phase(prefix_b, begin, end)
        by_b = {s["name"]: s for s in sb["sources"]}
        out["service"] = [{"name": s["name"], **{k: [s[k], by_b[s["name"]][k]] for k in service.SOURCE_FIELDS}}
                          for s in sa["sources"] if s["name"] in by_b
                          and any(s[k] != by_b[s["name"]][k] for k in service.SOURCE_FIELDS)]
    if all(Path(f"{p}.exit.{m}").is_file() for p in (prefix_a, prefix_b) for m in (begin, end)):
        ea, eb = exits.exit_phase(prefix_a, begin, end), exits.exit_phase(prefix_b, begin, end)
        def needed(e):
            return sum(m + h + x for m, h, x, _ in e.values())
        out["exits"] = {"needed": [needed(ea), needed(eb)],
                        "accesses": [sum(v[3] for v in ea.values()), sum(v[3] for v in eb.values())]}
    return out


def _signed(value: int) -> str:
    return f"{value:+,}"


def census_report(data: dict, limit: int, symbols: census.Symbols) -> str:
    begin, end = data["phase"]
    t = data["totals"]
    (runs_a, packets_a), (runs_b, packets_b) = t["blocks"]["a"], t["blocks"]["b"]
    lines = [f"census diff {begin} -> {end}: A {data['a']}, B {data['b']}",
             f"block runs {runs_a:,} -> {runs_b:,} ({_signed(runs_b - runs_a)}), "
             f"packets {packets_a:,} -> {packets_b:,} ({_signed(packets_b - packets_a)})",
             f"MMR reads {t['mmio']['a'][0]:,} -> {t['mmio']['b'][0]:,}, "
             f"writes {t['mmio']['a'][1]:,} -> {t['mmio']['b'][1]:,}"]
    first = data["first_difference"]
    lines.append("guest work identical at every mark" if not first else
                 f"guest work first differs in {first['after']} -> {first['mark']}: " + "; ".join(first["lines"][:3]))
    blocks = data["blocks"]
    if not blocks:
        lines.append("every block ran the same number of times with the same packets")
    for title, rows in (("most packets gained in B", sorted(blocks, key=lambda r: -r["delta"][1])),
                        ("most packets lost in B", sorted(blocks, key=lambda r: r["delta"][1]))):
        rows = [r for r in rows if (r["delta"][1] > 0) == title.endswith("gained in B") and r["delta"][1]][:limit]
        if not rows:
            continue
        lines += ["", f"{title}:", f"{'block':>10} {'runs A':>12} {'runs B':>12} {'packets A':>13} {'packets B':>13} "
                  f"{'delta':>12}  symbol"]
        for r in rows:
            note = "(only in A)" if r["only"] == "a" else "(only in B)" if r["only"] == "b" else ""
            label = " ".join(x for x in (symbols.name(r["key"]), note) if x)
            lines.append(f"0x{r['key']:08x} {r['a'][0]:>12,} {r['b'][0]:>12,} {r['a'][1]:>13,} {r['b'][1]:>13,} "
                         f"{_signed(r['delta'][1]):>12}  {label}")
    reshaped = [r for r in blocks if r["delta"][0] and not r["delta"][1]]
    if reshaped:
        lines.append(f"{len(reshaped)} blocks ran a different number of times for the same packets: "
                     "the blocks were formed differently")
    if data["mmio"]:
        lines += ["", f"{'MMR':>10} {'reads A':>12} {'reads B':>12} {'writes A':>12} {'writes B':>12}"]
        for r in sorted(data["mmio"], key=lambda r: -(abs(r["delta"][0]) + abs(r["delta"][1])))[:limit]:
            lines.append(f"0x{r['key']:08x} {r['a'][0]:>12,} {r['b'][0]:>12,} {r['a'][1]:>12,} {r['b'][1]:>12,}")
    for s in data.get("service", [])[:limit]:
        lines.append(f"service {s['name']}: " + ", ".join(f"{k} {s[k][0]:,} -> {s[k][1]:,}"
                                                        for k in service.SOURCE_FIELDS if s[k][0] != s[k][1]))
    if "exits" in data:
        e = data["exits"]
        lines.append(f"runs that needed the host {e['needed'][0]:,} -> {e['needed'][1]:,}; guest memory accesses "
                     f"{e['accesses'][0]:,} -> {e['accesses'][1]:,}")
    return "\n".join(lines)


def _last_translation(trace_data: dict, end: Optional[str]) -> Dict[int, compilation.Translation]:
    """The last successful translation of each block before mark `end` (or
    in the whole run): the code that ran last."""
    stop = float("inf")
    if end:
        found = trace.marks(trace_data)
        if end not in found:
            raise trace.TraceError(f"mark {end!r} is not in the trace")
        stop = found[end]["ts"]
    out = {}
    for t in sorted(compilation.translations(trace_data), key=lambda t: t.begin_us):
        if t.ok and t.begin_us < stop:
            out[t.pc] = t
    return out


def compile_diff(run_a: Path, run_b: Path, window: Optional[Tuple[str, str]],
                 weights: Optional[Path] = None) -> dict:
    """Blocks whose machine code differs between two runs (by the code hash
    of their last translation before the phase ends), those compiled on one
    side only, and with a census run, how much of the phase's executed work
    the changed code covers."""
    # The code a phase ran was compiled any time before its end, not only
    # inside it: take each block's last translation up to the end.
    end = window[1] if window else None
    ta, tb = (_last_translation(trace.load(str(r / "trace.json")), end) for r in (run_a, run_b))
    for side, spans in (("A", ta), ("B", tb)):
        if spans and not compilation.has_shape(list(spans.values())):
            raise ValueError(f"run {side} has no code hashes (a binary before them): nothing to compare")
    blocks = []
    for pc in set(ta) | set(tb):
        a, b = ta.get(pc), tb.get(pc)
        state = "only a" if b is None else "only b" if a is None else \
            "same" if a.object_hash == b.object_hash else "changed"
        blocks.append({"pc": pc, "state": state,
                       "a": {"ir_insns": a.ir_insns, "object_bytes": a.object_bytes, "cpu_ns": a.cpu_ns} if a else None,
                       "b": {"ir_insns": b.ir_insns, "object_bytes": b.object_bytes, "cpu_ns": b.cpu_ns} if b else None})
    out = {"schema": SCHEMA, "kind": "compile", "window": list(window) if window else None,
           "a": str(run_a), "b": str(run_b), "blocks": blocks,
           "counts": {state: sum(1 for b in blocks if b["state"] == state)
                      for state in ("same", "changed", "only a", "only b")}}
    if weights:
        if not window:
            raise ValueError("--census weighs blocks by a phase's work: give --phase")
        work = census.phase(weights / "census", "pc", *window)
        total = sum(p for _, p in work.values()) or 1
        for b in blocks:
            runs, packets = work.get(b["pc"], (0, 0))
            b["runs"], b["packets"] = runs, packets
        out["weights"] = str(weights)
        out["packets_total"] = total
        out["changed_packets"] = sum(b["packets"] for b in blocks if b["state"] == "changed")
        out["unchanged_packets"] = sum(b["packets"] for b in blocks if b["state"] == "same")
        out["one_side_packets"] = sum(b["packets"] for b in blocks if b["state"].startswith("only"))
    return out


def compile_report(data: dict, limit: int, symbols: census.Symbols) -> str:
    c = data["counts"]
    where = f" {data['window'][0]} -> {data['window'][1]}" if data["window"] else ""
    lines = [f"compile diff{where}: A {data['a']}, B {data['b']}",
             f"blocks with the same code {c['same']:,}, different code {c['changed']:,}, compiled only in A "
             f"{c['only a']:,}, only in B {c['only b']:,}"]
    weighted = "packets_total" in data
    if weighted:
        total = data["packets_total"]
        lines.append(f"weighted by the census {data['weights']}: blocks whose code changed executed "
                     f"{data['changed_packets'] / total * 100:.1f}% of the phase's packets, unchanged ones "
                     f"{data['unchanged_packets'] / total * 100:.1f}%, compiled on one side only "
                     f"{data['one_side_packets'] / total * 100:.1f}%")
    changed = [b for b in data["blocks"] if b["state"] == "changed"]
    key = (lambda b: -b["packets"]) if weighted else (lambda b: -abs(b["b"]["object_bytes"] - b["a"]["object_bytes"]))
    if changed:
        lines += ["", f"{'block':>10} {'IR A':>7} {'IR B':>7} {'bytes A':>8} {'bytes B':>8} {'ms A':>7} {'ms B':>7}"
                  + (f" {'packets':>13} {'share':>6}" if weighted else "") + "  symbol"]
        for b in sorted(changed, key=key)[:limit]:
            row = (f"0x{b['pc']:08x} {b['a']['ir_insns'] or 0:>7} {b['b']['ir_insns'] or 0:>7} "
                   f"{b['a']['object_bytes'] or 0:>8} {b['b']['object_bytes'] or 0:>8} "
                   f"{b['a']['cpu_ns'] / 1e6:7.2f} {b['b']['cpu_ns'] / 1e6:7.2f}")
            if weighted:
                row += f" {b['packets']:>13,} {b['packets'] / data['packets_total'] * 100:5.1f}%"
            lines.append(row + f"  {symbols.name(b['pc'])}")
    for side in ("a", "b"):
        only = [b for b in data["blocks"] if b["state"] == f"only {side}"]
        if only:
            lines.append(f"compiled only in {side.upper()}: " + ", ".join(f"0x{b['pc']:08x}" for b in only[:limit])
                         + (" ..." if len(only) > limit else ""))
    lines.append("Different code says where a change reached generated code; it says nothing about how fast "
                 "either side ran.")
    return "\n".join(lines)


def write_json(data: dict, path: Path) -> None:
    path.write_text(json.dumps(data, indent=1) + "\n")
