# Architecture

HackberryPiOS is split into a **UI-agnostic core** and a **Textual UI**. The
core knows nothing about the UI; the UI knows nothing about how a scan is
implemented. This keeps each part testable and lets the same logic power the
TUI, the `--cli` mode, and ad-hoc scripts.

```
┌───────────────────────────────────────────────┐
│ app.py  (Textual UI)                            │
│  • tabs, tables, inputs, key bindings           │
│  • @work(thread=True) workers call core code    │
│  • call_from_thread() pushes results to widgets │
└───────────────┬─────────────────────────────────┘
                │ uses
┌───────────────▼─────────────────────────────────┐
│ core/state.py  (AppState)                        │
│  • holds all results in one place                │
│  • orchestrates multi-step scans                 │
│  • assess() → recommendations; to_report()→JSON  │
└───────────────┬─────────────────────────────────┘
                │ calls
┌───────────────▼─────────────────────────────────┐
│ core/*.py  (scanners — pure functions/dataclasses)│
│  netinfo discovery ports shares dc printers wifi  │
│  speedtest security recommendations               │
└───────────────┬─────────────────────────────────┘
                │ via
┌───────────────▼─────────────────────────────────┐
│ core/utils.run()  → subprocess → CLI tools        │
│  graceful degradation when a tool is missing      │
└───────────────────────────────────────────────────┘
```

## Design principles

**Delegate, don't reinvent.** Network scanning is a solved problem; we shell
out to `nmap`, `arp-scan`, `smbclient`, `iw`/`nmcli`, `avahi-browse`, etc., and
parse their output. This keeps the codebase small and the results trustworthy
on a low-power handheld.

**Graceful degradation.** `utils.have()` checks each tool before use.
`utils.missing_tools()` powers the dashboard's "what to install" hint. Where
practical there are pure-Python fallbacks (e.g. a threaded TCP-connect port
scanner when nmap is absent, the ARP cache when arp-scan can't run).

**Everything returns dataclasses.** No scanner prints or touches the UI. This
makes `state.to_report()` a straightforward recursive serialisation and makes
the logic easy to unit-test or reuse.

**Responsive UI.** Scans are blocking and can take seconds to minutes, so every
scan runs in a Textual thread worker. Results are pushed back to widgets with
`call_from_thread()`; the UI never freezes.

**Incremental assessment.** `recommendations.build()` accepts every result as
optional, so the recommendation engine produces useful output after a single
scan and refines it as more data arrives.

## Adding a new check

1. Create `core/yourcheck.py` returning a dataclass result.
2. Add a `run_yourcheck()` method to `AppState` that stores the result and (if
   relevant) appends `security.Finding`s.
3. Surface it in `recommendations.build()` and `state.to_report()`.
4. Add a tab in `app.py`: a `_compose_yourcheck()` method, a button route, a
   `@work(thread=True)` worker, and an `_after_yourcheck()` UI updater.

## Threading model

- One `AppState` instance lives on the `App`.
- Workers mutate `AppState` off the main thread. Because the user triggers
  scans sequentially via the UI and each `_after_*` callback re-reads state on
  the main thread, contention is minimal. The heavy parallelism (per-host
  probing) is contained inside each scanner via `ThreadPoolExecutor`.
