#!/usr/bin/env python3
"""Apply the final machine-readable gate before the explicit Full run."""

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from Perf_Exp_05_3.scripts.common import dump_json, read_csv  # noqa: E402


def truth(value):
    return str(value).lower() == "true"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("standard_run"); parser.add_argument("exp12_run")
    args = parser.parse_args()
    standard, exp12 = Path(args.standard_run).resolve(), Path(args.exp12_run).resolve()
    validation = json.loads((standard / "validation.json").read_text())
    correctness = json.loads((standard / "correctness.json").read_text())
    exp12v = json.loads((exp12 / "validation.json").read_text())
    ops = read_csv(standard / "operation_count_comparison.csv")
    exp03 = read_csv(standard / "raw/exp03_transform_vs_J.csv")
    exp04 = read_csv(standard / "raw/exp04_transform_vs_tI.csv")
    storage = read_csv(standard / "fxabe_full_storage_breakdown.csv")
    stats = read_csv(standard / "fabeo_core_statistics.csv")
    occurrence = all((r["scheme"] != "FXABE-05.3 Core" or int(r["G2_exp"]) == 8) and
                     (r["scheme"] != "FXABE-NoOccurrence Core" or int(r["G2_exp"]) == int(r["ell"]))
                     for r in ops)
    g2 = all(r["scheme"] != "FXABE-05.3 Core" or int(r["G2_exp"]) == 8 for r in ops)
    pair = all(int(float(r["pair_count"])) == 3 + int(float(r["t_I"]))
               for r in exp03 + exp04 if r["phase"].startswith("Transform") and r["pair_count"])
    storage_ok = True
    for ell in set(r["ell"] for r in storage):
        selected = [r for r in storage if r["ell"] == ell]
        storage_ok &= sum(int(r["serialized_bytes"]) for r in selected) == int(selected[0]["total_CT_bytes"])
    required_plots = {"03a_core_ciphertext_storage.png", "03b_fxabe_full_storage_breakdown.png",
                      "09b_online_decryption_breakdown.png", "11b_dual_vs_coupled.png"}
    storage_ok &= required_plots <= {p.name for p in (standard / "plots").glob("*.png")}
    exp12_expected = (exp12v["status"] == "PASS" and exp12v["failed_rows"] == 0 and
                      exp12v["legal_u"] == [80, 160, 320, 640])
    real_fx = correctness.get("success", False) and all(x["no_exact_locator"] for x in exp12v["gates"])
    revocation = (ROOT / "Perf_Exp_05_3/docs/REVOCATION_SCALING_AUDIT.md").exists()
    comparable = any(truth(r["median_ci_overlap"]) for r in stats) and not all(
        float(r["fxabe_over_fabeo"]) < 1 for r in stats)
    gates = {
        "EXP01_EXP09_accounting_consistent": (ROOT / "Perf_Exp_05_3/docs/EXP01_EXP09_ACCOUNTING_AUDIT.md").exists(),
        "FABEO_vs_FXABE_interpretation": "COMPARABLE" if comparable else "INCONCLUSIVE",
        "occurrence_reuse": occurrence, "G2_count_is_c_max": g2,
        "transform_pair_invariant": pair, "storage_accounting": storage_ok,
        "policy_oprf_u_sensitivity": "EXPECTED" if exp12_expected else "INCONCLUSIVE",
        "real_FX": real_fx, "revocation_lifecycle": revocation,
        "unresolved_anomaly": bool(validation.get("errors") or validation.get("anomalies")),
        "standard_validation": validation.get("valid", False),
        "standard_correctness": correctness.get("success", False),
    }
    full_ready = (all(gates[k] for k in ("EXP01_EXP09_accounting_consistent", "occurrence_reuse",
                                          "G2_count_is_c_max", "transform_pair_invariant",
                                          "storage_accounting", "real_FX", "revocation_lifecycle",
                                          "standard_validation", "standard_correctness")) and
                  gates["policy_oprf_u_sensitivity"] == "EXPECTED" and
                  not gates["unresolved_anomaly"])
    gates["FULL_READY"] = full_ready
    dump_json(standard / "PRE_FULL_GATE.json", gates)
    lines = ["# PRE-FULL Audit", "",
             f"1. EXP01/EXP09 accounting consistent: **{'PASS' if gates['EXP01_EXP09_accounting_consistent'] else 'FAIL'}**",
             f"2. FABEO vs FXABE statistical interpretation: **{gates['FABEO_vs_FXABE_interpretation']}**",
             f"3. Occurrence reuse: **{'PASS' if occurrence else 'FAIL'}**",
             f"4. 05.3 G2 count: **{'c_max' if g2 else 'WRONG'}**",
             f"5. Transform pair_count = 3+t_I: **{'PASS' if pair else 'FAIL'}**",
             f"6. Storage accounting: **{'PASS' if storage_ok else 'FAIL'}**",
             f"7. Policy OPRF u sensitivity: **{gates['policy_oprf_u_sensitivity']}**",
             f"8. Real FX: **{'PASS' if real_fx else 'FAIL'}**",
             f"9. Revocation lifecycle: **{'PASS' if revocation else 'FAIL'}**",
             f"10. Unresolved anomaly: **{'YES' if gates['unresolved_anomaly'] else 'NO'}**",
             f"11. FULL_READY: **{'YES' if full_ready else 'NO'}**", "",
             "The gate references the frozen Standard raw samples and independent EXP-12 supplemental run. "
             "It does not mutate either raw dataset."]
    (ROOT / "Perf_Exp_05_3/docs/PRE_FULL_AUDIT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("PRE_FULL_AUDIT_%s" % ("PASS" if full_ready else "FAIL"))
    if not full_ready:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
