"""Config-driven tiered sampling plans used by dry-run and runtime estimates."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Sampling:
    warmup: int
    repeats: int
    placements: int

    @property
    def formal_samples(self):
        return self.repeats * self.placements

    @property
    def warmup_invocations(self):
        return self.warmup * self.placements


def parse_sampling(value, placement_dependent=True):
    if not isinstance(value, dict):
        raise ValueError("sampling must be a YAML mapping")
    result = Sampling(
        warmup=int(value["warmup"]),
        repeats=int(value["repeats"]),
        placements=int(value.get("placements", 1)),
    )
    if result.warmup < 0 or result.repeats < 1 or result.placements < 1:
        raise ValueError("sampling requires warmup>=0, repeats>=1, placements>=1")
    if not placement_dependent and result.placements != 1:
        raise ValueError("placement-independent experiment must use placements=1")
    return result


def endpoint_values(section):
    values = list(map(int, section["n"]))
    endpoint = section.get("large_endpoint", {})
    if endpoint.get("enabled", False):
        large = int(endpoint["n"])
        if large not in values:
            values.append(large)
    return values


def sampling_for_n(section, n):
    endpoint = section.get("large_endpoint", {})
    if endpoint.get("enabled", False) and int(n) == int(endpoint["n"]):
        return parse_sampling(endpoint["sampling"])
    return parse_sampling(section["sampling"])


def _row(experiment, tier, points, sampling, operation):
    return {
        "experiment": experiment,
        "tier": tier,
        "points": int(points),
        "placements": sampling.placements,
        "repeats": sampling.repeats,
        "warmups": sampling.warmup,
        "formal_samples": int(points) * sampling.formal_samples,
        "warmup_invocations": int(points) * sampling.warmup_invocations,
        "estimated_crypto_invocations":
            int(points) * (sampling.formal_samples + sampling.warmup_invocations),
        "operation": operation,
    }


def workload_plan(config):
    rows = []
    exp01 = config["exp01"]
    base_n = list(map(int, exp01["n"]))
    ratios = list(exp01["ratios"])
    rows.append(_row("Exp01", "default", len(base_n) * len(ratios),
                     parse_sampling(exp01["sampling"]), "RevKeyUpt"))
    large = exp01.get("large_endpoint", {})
    if large.get("enabled", False):
        rows.append(_row("Exp01", "large_endpoint", len(ratios),
                         parse_sampling(large["sampling"]), "RevKeyUpt"))

    exp02 = config["exp02"]
    exp02_sampling = parse_sampling(exp02["sampling"])
    rows.append(_row("Exp02", "default", len(exp02["r_v"]), exp02_sampling,
                     "RevKeyUpt"))
    rows.append(_row("Exp03", "derived_from_Exp02", len(exp02["r_v"]),
                     Sampling(0, 1, 1), "no crypto; CSV view"))
    rows[-1].update({"formal_samples": 0, "warmup_invocations": 0,
                     "estimated_crypto_invocations": 0})

    exp04 = config["exp04"]
    rows.append(_row("Exp04", "default", len(exp04["r_v"]),
                     parse_sampling(exp04["sampling"]), "Transform"))

    exp05 = config["exp05"]
    direct = exp05["direct_comparison"]
    # Each n has two independently measured real modes.
    rows.append(_row("Exp05-A", "direct_comparison", 2 * len(direct["n"]),
                     parse_sampling(direct["sampling"]),
                     "Dual or Coupled epoch transition"))
    dual = exp05["dual_scalability"]
    reuse_values = endpoint_values(dual)
    source_values = set(endpoint_values(exp01))
    if not set(reuse_values).issubset(source_values):
        raise ValueError("Exp05-B n values must be available in Exp01")
    reused = sum(sampling_for_n(exp01, n).formal_samples for n in reuse_values)
    reuse_row = _row(
        "Exp05-B", "reused_Exp01_5pct", len(reuse_values),
        Sampling(0, 1, 1),
        "reused from Exp01; 0 additional cryptographic benchmark samples",
    )
    reuse_row.update({
        "placements": 0, "repeats": 0, "warmups": 0,
        "formal_samples": 0, "warmup_invocations": 0,
        "estimated_crypto_invocations": 0, "reused_formal_samples": reused,
    })
    rows.append(reuse_row)

    exp06 = config["exp06"]
    rows.append(_row("Exp06", "placement_independent", len(exp06["S"]),
                     parse_sampling(exp06["sampling"], False), "PrivacyKeyUpt"))
    return rows


def plan_totals(config):
    rows = workload_plan(config)
    return {
        "formal_samples": sum(row["formal_samples"] for row in rows),
        "warmup_invocations": sum(row["warmup_invocations"] for row in rows),
        "estimated_crypto_invocations":
            sum(row["estimated_crypto_invocations"] for row in rows),
    }


def format_plan(config):
    rows = workload_plan(config)
    header = ("Experiment  Tier                 Points  Place  Repeat  Warmup  "
              "Formal  CryptoInvocations")
    lines = ["mode=%s" % config["mode"], header, "-" * len(header)]
    for row in rows:
        lines.append(
            "{experiment:<10} {tier:<20} {points:>6} {placements:>6} "
            "{repeats:>7} {warmups:>7} {formal_samples:>7} "
            "{estimated_crypto_invocations:>18}".format(**row)
        )
    totals = plan_totals(config)
    lines.append("Total formal samples: %d" % totals["formal_samples"])
    lines.append("Total warmup invocations: %d" % totals["warmup_invocations"])
    lines.append("Exp03 performs no benchmark operations and reuses Exp02 raw rows.")
    lines.append("Exp05-B reused from Exp01; 0 additional cryptographic benchmark samples.")
    exp01, exp02, exp04, exp05, exp06 = (
        config[name] for name in ("exp01", "exp02", "exp04", "exp05", "exp06")
    )
    lines.extend([
        "Parameters:",
        "  Exp01 n=%s ratios=%s large_endpoint=%s" %
        (exp01["n"], exp01["ratios"],
         bool(exp01.get("large_endpoint", {}).get("enabled", False))),
        "  Exp02/03 n=%s r_v=%s" % (exp02["n"], exp02["r_v"]),
        "  Exp04 n=%s r_v=%s N=%s ell=%s fixed_r=%s" %
        (exp04["n"], exp04["r_v"], exp04["N"], exp04["ell"], exp04["r"]),
        "  Exp05-A n=%s ratio=%s S=%s ell=%s u=%s" %
        (exp05["direct_comparison"]["n"], exp05["revocation_ratio"],
         exp05["S"], exp05["ell"], exp05["policy_unique_attributes"]),
        "  Exp05-B n=%s large_endpoint=%s (reused from Exp01 5%%)" %
        (exp05["dual_scalability"]["n"], bool(exp05["dual_scalability"].get(
            "large_endpoint", {}).get("enabled", False))),
        "  Exp06 S=%s (placement-independent)" % exp06["S"],
    ])
    return "\n".join(lines)
