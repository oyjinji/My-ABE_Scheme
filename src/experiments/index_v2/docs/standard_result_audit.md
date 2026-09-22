# Standard result audit before the five-index revision

Audited run: `standard-20260729T030653.543455Z-8fd0aa8b`.

The audit read the run's three raw CSV files, three summary CSV files,
`all_metrics.json`, validation and experiment reports, environment/config, and
all four PNG/PDF figure pairs. The run passed validation with F1=960, F2=400,
and F3=40 raw rows. These historical files are retained unchanged. Their labels
`Cuckoo` and `Xor` refer to the membership-filter plus locator adapters now
displayed as `Cuckoo+Locator` and `Xor+Locator`.

## Evidence

1. FX-ABF Build returned to overall linear scaling after the segmented FusePos
   fix. Its F1-A medians at `u=2048` and `u=8192` were 132.33 ms and
   529.92 ms, a 4.00x increase for a 4x increase in tokens. The earlier
   `u=16384` retry anomaly is therefore not present in this standard matrix.
2. FX-ABF integrated space was 49.02 bytes/token at `u=8192`. This includes
   retrieval slots, encrypted PStore, and metadata, not only the slot array.
3. At `u=8192`, Bloom+Locator, Cuckoo+Locator, and Xor+Locator used 71.51,
   74.01, and 72.61 integrated bytes/token. Their exact locator and PStore are
   included, making the comparison commensurate.
4. F2-B Core Transform medians nearly overlap across the four historical
   indexes. Recorded pairing counts are 10, 18, 34, 66, and 130 for
   `r=4,8,16,32,64`, exactly `2+2r`.
5. In F2-A (`N=32,r=8`), Core Transform was about 59 ms while Total Transform
   was about 61--63 ms. The two revocation pairings and 16 row pairings
   therefore dominate Total Transform; index differences contribute only a
   small fraction.
6. The empirical advantage of FX-ABF in this run is integrated space. It was
   not consistently the fastest builder, and its Total Transform curve was not
   the lowest. No claim that FX-ABF must be fastest is supported.

## Figure interpretation

- `f1_build_time` shows integrated-index wall-clock Build time, even though its
  historical title said “Filter Build Time”; the revised title states the
  integrated semantics explicitly.
- `f1_index_space` correctly uses integrated bytes/token.
- `f2_transform_scaling` is pairing dominated and is moved to supplemental
  status in the revised plotting pipeline.
- `f2_core_transform` is a shared ABE/pairing control, not an index-speed claim.

This audit is descriptive only. It does not rewrite, relabel, remove, or
resummarize the preserved standard measurements.
