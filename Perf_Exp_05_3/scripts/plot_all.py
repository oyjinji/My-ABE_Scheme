#!/usr/bin/env python3
"""Generate the compact paper-oriented plot set from retained raw samples."""

import argparse
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from Perf_Exp_05_3.scripts.common import read_csv  # noqa: E402


COLORS={"FXABE-05.3 Core":"#1b9e77","FXABE-NoOccurrence Core":"#d95f02","FABEO":"#7570b3","FXABE-05.3":"#1b9e77"}


def _num(v):
    try:return float(v)
    except:return None


def _median(rows,x,series,value="time_ns",predicate=lambda r:True):
    groups=defaultdict(list)
    for r in rows:
        if predicate(r) and r.get(x)!="" and r.get(value)!="": groups[(r.get(series,""),float(r[x]))].append(float(r[value]))
    out=defaultdict(list)
    for (name,xv),vals in groups.items():out[name].append((xv,statistics.median(vals)))
    return {k:sorted(v) for k,v in out.items()}


def _line(ax,data,scale=1e-6,ylabel="Time (ms)"):
    for name,points in data.items():
        if not points:continue
        ax.plot([x for x,_ in points],[y*scale for _,y in points],marker="o",label=name,color=COLORS.get(name))
    ax.set_ylabel(ylabel);ax.grid(alpha=.25);ax.legend(fontsize=8)


def _save(fig,path):
    fig.tight_layout();fig.savefig(path,dpi=170);plt.close(fig)


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run_dir");args=parser.parse_args();run=Path(args.run_dir);raw=run/"raw";plots=run/"plots"
    # EXP-00
    rows=read_csv(raw/"exp00_group_ops.csv"); data=_median(rows,"replicate","component")
    fig,ax=plt.subplots(figsize=(8,4)); names=list(data); vals=[statistics.median([y for _,y in data[n]])/1e6 for n in names]
    ax.bar(names,vals,color="#4c78a8");ax.set_ylabel("Time (ms)");ax.tick_params(axis="x",rotation=35);ax.set_title("EXP-00 MNT224 Primitive Costs");_save(fig,plots/"exp00_group_ops.png")
    # 01 core
    rows=read_csv(raw/"exp01_encrypt.csv"); data=_median(rows,"ell","scheme",predicate=lambda r:r["phase"]=="Encrypt Core")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Policy rows ell");ax.set_title("Encrypt Core Time vs ell");_save(fig,plots/"01_encrypt_core.png")
    # 02 full encrypt breakdown
    data=_median(rows,"ell","phase",predicate=lambda r:r["scheme"]=="FXABE-05.3 Full" and r["phase"]!="Full Encrypt")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Policy rows ell");ax.set_title("FXABE Full Encrypt Breakdown");_save(fig,plots/"02_full_encrypt_breakdown.png")
    # 03 storage
    rows=read_csv(raw/"exp02_storage.csv");data=_median(rows,"ell","scheme",value="serialized_bytes",predicate=lambda r:r["component"]=="total_CT_bytes")
    fig,ax=plt.subplots();_line(ax,data,scale=1/1024,ylabel="Canonical bytes (KiB)");ax.set_xlabel("Policy rows ell");ax.set_title("Ciphertext Storage");_save(fig,plots/"03_ciphertext_storage.png")
    # 04 Transform vs J
    rows=read_csv(raw/"exp03_transform_vs_J.csv");data=_median(rows,"J","phase")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("|J|");ax.set_title("Transform Decomposition vs J");_save(fig,plots/"04_transform_vs_J.png")
    # 05 tI
    rows=read_csv(raw/"exp04_transform_vs_tI.csv");data=_median(rows,"t_I","scheme")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("t_I");ax.set_title("Transform vs Occurrence Slots");ax2=ax.twinx();p=_median(rows,"t_I","scheme",value="pair_count");
    for name,points in p.items():ax2.plot([x for x,_ in points],[y for _,y in points],"k--",alpha=.6,label="pair count")
    ax2.set_ylabel("Pairings");_save(fig,plots/"05_transform_vs_tI.png")
    # 06 cmax
    rows=read_csv(raw/"exp05_cmax.csv");fig,axes=plt.subplots(1,3,figsize=(12,3.6))
    for ax,phase,value,scale,label in zip(axes,["Encrypt Core","Storage","Transform Total"],["time_ns","serialized_bytes","time_ns"],[1e-6,1/1024,1e-6],["ms","KiB","ms"]):
        d=_median(rows,"c_max","scheme",value=value,predicate=lambda r,p=phase:r["phase"]==p);_line(ax,d,scale=scale,ylabel=label);ax.set_title(phase);ax.set_xlabel("c_max")
    _save(fig,plots/"06_cmax_ablation.png")
    # 07 build
    rows=read_csv(raw/"exp06_fx_build.csv");data=_median(rows,"u","phase")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Distinct tokens u");ax.set_title("Real FX/PStore Build");_save(fig,plots/"07_fx_build.png")
    # 08 query
    rows=read_csv(raw/"exp07_fx_query.csv");data=_median(rows,"N","phase")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Query tokens N");ax.set_title("Real FX Query");_save(fig,plots/"08_fx_query.png")
    # 09 E2E
    rows=read_csv(raw/"exp08_e2e_breakdown.csv");data=_median(
        rows,"ell","phase",predicate=lambda r:r["workload"]=="OR"
    )
    fig,ax=plt.subplots(figsize=(8,5));_line(ax,data);ax.set_xlabel("Policy rows ell");ax.set_title("FXABE End-to-End Breakdown");_save(fig,plots/"09_e2e_breakdown.png")
    # 10 core comparison
    rows=read_csv(raw/"exp11_fabeo_core.csv");data=_median(rows,"ell","scheme",predicate=lambda r:r["phase"] in ("Encrypt",))
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Policy rows ell");ax.set_title("FABEO Core Comparison: Encrypt");_save(fig,plots/"10_fabeo_core.png")
    # 11 revocation
    rows=read_csv(raw/"exp10_revocation.csv");data=_median(rows,"n_users","phase",predicate=lambda r:r["phase"]=="RevKeyUpt vs n")
    fig,ax=plt.subplots();_line(ax,data);ax.set_xlabel("Registered users n");ax.set_title("Revocation Scaling");_save(fig,plots/"11_revocation.png")
    print("PLOTS_PASS")


if __name__=="__main__":main()
