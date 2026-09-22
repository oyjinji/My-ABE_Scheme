"""Encrypt / Transform operation ledgers.

Static counts derived by reading the real code (src/core/fabeo22cp, src/core/fxabe_rev)
combined with measured per-operation costs (results/operation_costs.csv) from
this MNT224 backend.  Writes:

  results/encrypt_operation_ledger.csv
  results/transform_operation_ledger.csv

These are attribution tables, not a formal benchmark.  Counts marked
``unknown`` where the code makes them data-dependent.
"""

import csv
import os

# Inputs are always read from the committed results directory; only the
# outputs follow GLOBAL_EXP_AUDIT_OUT, so this can be run without rewriting the
# committed ledgers. Unset, it writes where it always has.
HERE = os.path.dirname(os.path.abspath(__file__))
IN_DIR = os.path.join(HERE, "results")
OUT_DIR = os.environ.get("GLOBAL_EXP_AUDIT_OUT") or IN_DIR


def load_costs():
    costs = {}
    p = os.path.join(IN_DIR, "operation_costs.csv")
    for r in csv.DictReader(open(p)):
        costs[r["operation"]] = float(r["ms_per_op"])
    return costs


def main():
    c = load_costs()
    # per-op ms (measured on this backend)
    pair = c["pair(g1,g2)"]
    g1e = c["g1 ** z"]
    g2e = c["g2 ** z"]
    gte = c["gt ** z"]
    h1 = c["hash->G1"]
    h2 = c["hash->G2"]
    hz = c["hash->ZR"]

    # ------------------------------------------------------------------
    # Encrypt ledger.  counts per ciphertext at policy_rows=l (OR => cols=1)
    # ------------------------------------------------------------------
    enc = []
    # columns: operation, FABEO22 count, FABEO22 est_ms(l), FXABE-Base count,
    #          Base est_ms(l), FXABE-Full count, Full est_ms(l), scope
    E = []
    # fixed ZR randoms
    E.append(["ZR random (fixed)", "2", 0, "1 (vector)", 0, "1 (vector)", 0, "ciphertext"])
    E.append(["ZR random (per row, r_i)", "0", 0, "l", "l*0", "l", "l*0", "row"])
    # G1 exponentiation
    E.append(["G1 exp (fixed)", "0", 0, "2 (C, C_rev)", "2*g1e", "2 (C, C_rev)", "2*g1e", "ciphertext"])
    E.append(["G1 exp (per row)", "2 (bHash^Mivtop, attrHash^sprime)",
              "2*l*g1e", "2 (g1^(a*lambda), q^-r)", "2*l*g1e",
              "3 (g1^(a*lambda), q^-r, H1^kappa)", "3*l*g1e", "row"])
    # G2 exponentiation
    E.append(["G2 exp (fixed)", "2 (g2_s1, g2_sprime)", "2*g2e", "0", 0, "0", 0, "ciphertext"])
    E.append(["G2 exp (per row)", "0", 0, "1 (C2=g2^r)", "l*g2e", "1 (C2=g2^r)", "l*g2e", "row"])
    # GT exponentiation
    E.append(["GT exp (fixed)", "1 (Cp)", "1*gte", "1 (E=egg^s)", "1*gte", "1 (E=egg^s)", "1*gte", "ciphertext"])
    # hash to G1
    E.append(["hash->G1 (fixed)", "1 (bHash)", "1*h1", "0", 0, "0", 0, "ciphertext"])
    E.append(["hash->G1 (per row)", "1 (attrHash)", "l*h1", "1 (q=_direct_q)", "l*h1",
              "2 (H1 chi, H0 token)", "2*l*h1", "row"])
    # hash to ZR
    E.append(["hash->ZR (fixed)", "0", 0, "1 (epoch scalar)", "1*hz", "1 (epoch scalar)", "1*hz", "ciphertext"])
    # token serialize (G1)
    E.append(["G1 serialize (per row)", "0", 0, "0", 0, "1 (token_bytes)", "l*SER", "row"])
    # policy parsing / LSSS
    E.append(["policy parse -> MSP (fixed)", "1", "PP", "1", "PP", "1", "PP", "ciphertext"])
    E.append(["lambda dot product (per row)", "1 (len-1)", "l*ZD", "1", "l*ZD", "1", "l*ZD", "row"])
    # index build (Full only)
    E.append(["FX-ABF build (fixed + per posting)", "0", 0, "0", 0, "1 (u=l postings)", "IDX", "filter"])
    E.append(["PStore build (fixed + per posting)", "0", 0, "0", 0, "1", "PST", "pstore"])
    # KEM-DEM
    E.append(["kdf + AEAD (fixed)", "0", 0, "1", "KEM", "1", "KEM", "ciphertext"])

    with open(os.path.join(OUT_DIR, "encrypt_operation_ledger.csv"), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["operation", "fabeo_count", "fabeo_est", "base_count",
                    "base_est", "full_count", "full_est", "scope"])
        for row in E:
            w.writerow(row)

    # ------------------------------------------------------------------
    # Transform ledger.  counts per transform at l rows, m matched rows.
    # ------------------------------------------------------------------
    T = []
    # operation, fixed_count, fixed_cost, per_reconstruction_row_count,
    # per_row_cost, base_est(l), full_est(l), scope
    T.append(["pairing (revocation t0)", "2", "2*pair", "0", 0, "2*pair", "2*pair", "fixed"])
    T.append(["pairing (per matched row: pair(C1,K1)*pair(Kx,C2))", "0", 0,
              "2 per matched row", "2*pair", "2*m*pair", "2*m*pair", "per matched row"])
    T.append(["hash->ZR (epoch scalar)", "1", "1*hz", "0", 0, "1*hz", "1*hz", "fixed"])
    T.append(["path/cover set intersection", "1", "0", "0", 0, "~0", "~0", "fixed"])
    T.append(["C_rev integrity check (C**h_r)", "0", 0, "0", 0, "1 g1exp", "1*g1e", "fixed"])
    T.append(["index query (per user token)", "0", 0, "0", 0, "m", "m*QRY", "m*QRY", "per user token"])
    T.append(["direct row lookup (Base)", "0", 0, "1 (map attr->rows)", "~0", "0", 0, "fixed"])
    T.append(["reconstruction solve (final_dec)", "0", 0, "1", "GAUSS", "1", "GAUSS", "fixed"])
    T.append(["GT exp (final_dec, per nonzero coeff)", "0", 0,
              "1 for OR (else k)", "1*gte", "1*gte", "1*gte", "per nonzero coeff"])
    T.append(["kdf + AEAD decrypt (final_dec)", "0", 0, "1", "KEM", "1", "KEM", "fixed"])

    with open(os.path.join(OUT_DIR, "transform_operation_ledger.csv"), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["operation", "fixed_count", "fixed_est", "per_row_count",
                    "per_row_est", "base_est_formula", "full_est_formula", "scope"])
        for row in T:
            w.writerow(row)

    print("encrypt_operation_ledger.csv written")
    print("transform_operation_ledger.csv written")
    # quick headline numbers
    print("\nPer-row encrypt cost check (measured op costs):")
    print("  FABEO22/row = 2*g1e + h1 =", round(2 * g1e + h1, 3), "ms")
    print("  Base/row    = 2*g1e + g2e + h1 =", round(2 * g1e + g2e + h1, 3), "ms")
    print("  Full/row    = 3*g1e + g2e + 2*h1 + SER =", round(3 * g1e + g2e + 2 * h1, 3), "ms (excl serialize/index)")
    print("\nTransform pair cost per matched row = 2*pair =", round(2 * pair, 3), "ms")


if __name__ == "__main__":
    main()
