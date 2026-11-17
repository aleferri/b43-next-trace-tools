# b43-next-trace-tools

Tools for reverse-engineering Broadcom's `wl` driver and checking the b43
AC-PHY port against the captures. The driver and its tests are in
[b43-ac-wip](https://github.com/aleferri/b43-ac-wip), the captures in
[b43-next-traces](https://github.com/aleferri/b43-next-traces).

The host side is the Python package `b43trace`, in `src/`. Each tool is a
module of the package and runs as `b43trace <tool>`; `b43trace` alone lists
them. Each tool's `--help` and header say more. What runs on the router is
in `device/` ("Device side").

```sh
pip install -e '.[elf]'     # the extra brings pyelftools, for the ELF readers
b43trace trace-filter --retvals capture.txt folded.txt
python -m b43trace.pipeline.trace_filter --retvals capture.txt folded.txt
```

The blob tools also run `readelf` (binutils).

The tools that read the port or its unit harness take them from the
b43-ac-wip checkout named by `B43_TREE`. The wl-diag captures are taken from
its `router-data/`, or from `B43_DATA`, a directory with one subdirectory per
board. `anchors` resolves the capture paths of `capture-refs.conf` against
`B43_TREE`, which is what they are relative to. The wl-mmio-trap captures
are taken from the b43-next-traces checkout named by `B43_TRACES`.

## Trace pipeline

`test/unit/gates.sh` in b43-ac-wip runs the whole chain; none of it is
needed by hand for a gate. The comparison itself is `test/unit/compare.py`
(positional) and `test/unit/cmp_skip.py` (the score), there too.

- **decode-wl-diag** decodes the tracer's 28-byte big-endian records into
  text lines.
- **strip-other-core** removes the other wireless core's attach from the
  head of a capture (`wl` attaches every core at load).
- **trace-filter** removes instrumentation artefacts, always in this order:
  `--retvals` folds `RETVAL`/`ARGX` into the preceding op (without it every read
  is `val=UNDEFINED`), `--mod-reads` drops the internal read of every `MOD`,
  `--collapse` keeps only the `TBL` headers (it hides values: never compare
  collapsed traces op for op).
- **split-trace** cuts a trace into segments `--on mark` (cold sweeps),
  `mod`, `chanspec` (hot sweeps) or `gaps`; `--drop-between-runs` drops what
  lies between a run end and the next `mod COMING`.
- **timeline** lists the events after the bring-up (`WD`, `POLL`, `TPL`,
  `BSS_UP`, `NOISE`) with the watchdog phase and entry-turn shape.
- **beacon-reloads** says on which `conf_tx` passes the stack republished the
  beacon.
- **check-class-coverage** says which op classes a capture traces
  (`router-data/CLASS-COVERAGE.md` in b43-ac-wip).
- **compress-turns** shortens a weather-radar segment by removing whole
  blocks of 60 steady watchdog turns (a whole number of every period the driver
  counts, and an even number of beacon reloads); a TG789vac weather segment goes
  from ten minutes of gate to about ninety seconds.

### Bus-level captures

- **decode-wl-mmio** decodes the records of `wl-mmio-trap`, the raw accesses
  and the TX descriptors read at their index write.
- **mmio-captures** lists the wl-mmio-trap captures of b43-next-traces: per
  capture the label (`chip/board/set/stem`), the `-ops.txt.gz` mmio2ops
  decoded and the raw `.bin.gz`.
- **mmio2ops** decodes raw BAR0 accesses, an x86 mmiotrace, the binary
  records of `wl-mmio-trap` or the bpftrace and ftrace kprobe captures of
  the hybrid `wl`'s accessors, into the same vocabulary (`PHY.*`, `RAD.*`,
  `OBJ.*` with `sel=`, `MAC.*`, `REG.*`, plus `CC.*`, `SROM.RD`, `WRAP.*`,
  `PCIE.*`, `EROM.RD`). The window's core is inferred from unambiguous offsets
  (`--mark-windows`), except in the ftrace captures, which record the PCI
  config writes: there it is known, and the other cores' accesses are
  `CORE.*`. `--erom` lists the cores, `--srom` writes the SROM words.
  A 32-bit shared-memory access is split low half first.
- **ops-fold** `fold` rebuilds accessor-level ops from their bus footprint
  (the MOD mask as `rd ^ wr` is a lower bound); `report` lists window moves,
  polls, interrupt reasons, DMA activity and pauses.
- **fw-from-capture** rebuilds the ucode, initvals and bsinitvals b43
  loads from a bus capture of the stock `up`, as a firmware directory for
  `B43_FW_DIR` and as the raw ucode for b43-ac-wip's `test/d11sim` and
  b43-tools.
- **access-conditions** lists, for a stock bus capture and a b43 trace,
  the core state (reset, clocks, PHY clock and reset, MAC enable, PSM run,
  FORCEHT) each PHY and radio access happens in, and the polls each side
  makes.

## Libraries

- **`b43trace.tracelib`**: parsing, op normalisation, attribution of each op
  to its function through the marker stack, capture discovery: the wl-diag
  ones of `router-data/`, inside archives too (`archive.zip!inner.txt`), and
  the wl-mmio-trap ones of b43-next-traces. It reads gzipped traces. It
  defines "the same op".
- **`b43trace.d11.ac_txh`**: the d11 AC TX header as the stock driver hands
  it to DMA, shared by both decoders: packet info, rate blocks with the PHY
  TX control words, the PLCP read as L-SIG, HT-SIG or VHT-SIG-A, the 802.11
  header.
- **`b43trace.d11.ac_rxh`**: the d11 AC RX header as b43's `b43_rx()` reads
  it (frame length, PHY and MAC RX status, powers, padding, PLCP by frame
  type, 802.11 header), so a capture of the stock driver checks b43's RX
  path.
- **`b43trace.d11.template`**: a beacon or probe response template as
  written to template RAM: the bytes in front of the frame raw, then header,
  fixed fields and elements (SSID, DS, TIM, HT and VHT operation decoded).

## Analysis

- **fn-map**: `coverage` (ops found per port function, and the gaps), `span`,
  `fingerprints`. Pass the capture raw.
- **anchors**: resolves the `#NNNN` and `[capture-ref: …]` references in the
  source comments against `capture-refs.conf`; exits 1 when one does not
  resolve.
- **phase-absent**: which phases the stock driver does not run, over every
  address of the phase.
- **locate-missing-ops**: where in the port a missing op goes.
- **trova-sorgente**: where a written value comes from, trying every value
  read or written through every transformation.
- **find-readback-hardcodes**: registers the stock driver reads and the port
  writes as a literal.
- **reads**: `risk`, `intent`, `consumers`, `plan` for the reads the port
  discards (method in b43-ac-wip's `docs/retrace-todo.md`, "Discarded
  reads").
- **srom**: which written values are board data (`literals`, `correlate`,
  `verify`).
- **band-delta**: what the stock driver writes differently on 2.4 GHz,
  from two hops per band of one capture (folded with `ops-fold`); `--also`
  runs a second capture and marks each line same, other values or absent.
- **decorrelate-channels**: classifies each written key over N segments
  (invariant, channel-only, width-only, centre frequency, dynamic).
- **check-channeltab**: the 2069 channel table against every sweep segment.
- **rxiq-points**: extracts the RX IQ solve points and scores the solver.
- **ppr-invert**: inverts the PPR chain on a segment.
- **sweep-report**: per-channel score and register diff. Its denominator is
  the stock ops only, not comparable with `cmp_skip.py`'s.
- **probe-schedule**, **watchdog-turns**, **latch-placement**: measurement
  only, not used by the gates.
- **annotate-enables**, **dataflow**: debug utilities.

## Blob analysis

- **audit-hooks** replays `wl-diag`'s `pianifica()` offline on a `wl` object:
  prologue, detour window, return register, call sites, classes a capture would
  contain. Zero call sites is the misleading case: the hook arms, and the class
  stays empty because the function is inlined everywhere.
- **callsites-pic** finds call sites in a MIPS PIC module (`lui`/`addiu` +
  `jalr`).
- **mipsdis** is a minimal big-endian MIPS32 disassembler that reads hook
  signatures from prologues (`--prologo`).
- **cmp-funcs** compares same-name function bodies across `wl` builds.
- **gen-syms** builds the `klookup=` insmod line of `device/wl-diag/2-6-30`.
- **extract-ucode** extracts a `d11ucodeNN` blob from a `wl` object by
  symbol (`--rev`, `--symbol`, `--list`).
- **extract-acphy-tables-from-descriptor** (it generated
  `tables_phy_ac.c`), **extract-acphy-txgain**,
  **extract-chan-tuning-2069rev4**: one-shot table extractors.

## Device side

Under `device/`, each with its README:

- `wl-diag/`: the kernel module that hooks the stock `wl` driver's hardware
  accessors and records them, for kernel 3.4 and 2.6.30 on MIPS and 4.4 on
  ARM; **decode-wl-diag** reads its stream.
- `wl-mmio-trap/`: the register accesses `wl-diag` cannot see, trapped on
  `wl`'s register window; **decode-wl-mmio** and **mmio2ops** read its
  records. `make check` in its `tools/` runs the host checks of its
  pure-logic units.
- `wl-cc-dump/`: the ChipCommon PMU state of a running device, in `dmesg`.
- `devmem/`: `mempeek.c`, `pcicfg.c`, `memfind.c`, static helpers over
  `/dev/mem` and `/proc/bus/pci` (read MMIO, repoint `BAR0_WIN` onto
  ChipCommon, find a kernel variable by value); `mempeek` and `pcicfg` are
  there built for MIPS. Each source's header says how to build it.
- `wl-capture-scripts/`: `capture_cold_init.sh` (one `wl` reload per
  channel), `capture_hot_init.sh` (`{chanspec; up; wait; down}`, split with
  `--on chanspec`), `capture_profiles.sh` (the shared channel lists, copied next
  to them; `<bw>`, `<bw>dfs`, `<bw>meteo`), `capture_cold_tg789vac.sh` (see
  `router-data/tg789vac-v2/README.md` in b43-ac-wip).

## Checks on C sources

**csanity** checks C files without a compiler: `*/` in comments,
unterminated comments or literals, unbalanced brackets, a file-`static` symbol
used before its declaration, and (only for the `wl_diag.c` files, whose kernels
are C90 and `-Werror`) declaration after statement.
