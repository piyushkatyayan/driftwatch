# DRIFTWATCH — Pre/Post Upgrade Change Advisor (NX-OS)

A browser-based dashboard that compares a **pre-upgrade** and a **post-upgrade**
capture from a Cisco Nexus (NX-OS) switch, shows exactly **what changed**,
explains **why it likely changed**, and gives a **recommended fix** — with every
finding tagged by its evidence source and a **VERIFIED BY DESIGN** or
**VERIFY REQUIRED** stamp.

It is built for a VXLAN BGP-EVPN fabric (IS-IS underlay + BGP overlay + NVE),
but the generic diff works on any of the supported commands.

> This is **Step 1**: a self-contained prototype. All parsing and diffing run in
> the browser — nothing is uploaded to any server, so configs never leave your
> machine. **Step 2** swaps the built-in parsers for Cisco pyATS/Genie's 2700+
> parsers behind a small internal service, keeping this same interface.

---

## How to use it

1. Open `index.html` in any modern browser (double-click it, or host it — see below).
2. Put your captures into the two panes:
   - **Load sample** fills both panes with a worked example (an MTU-reset cascade) so you can see the tool in action immediately.
   - **Upload .txt** loads a capture file from disk.
   - Or just **paste** the text.
3. Click **Compare pre & post**.
4. Review each finding, then use **Accept / Flag for review / Roll back** to record your sign-off.

### What a capture should look like

Paste the raw output of your show-command run, **including the command echoes**,
e.g.:

```
LEAF-01# show running-config
 ...
LEAF-01# show isis adjacency
 ...
LEAF-01# show bgp vrf all all summary
 ...
```

The tool splits the capture on those command lines (with or without the
`hostname#` prompt). See `sample_pre.txt` / `sample_post.txt` for the exact
format — these are the same samples the **Load sample** button uses.

A convenient way to produce them on the box:

```
terminal length 0
show running-config
show ip arp
show module
show ip interface brief
show mac address-table
show version
show inventory
show boot
show ip route vrf all
show ip route
show isis adjacency
show bgp vrf all all summary
show isis database detail
show vpc
show nve peers
show interface status
show interface description
show lldp neighbors
show clock
```

(Log the session to a file, run this before the upgrade and again after, and
feed the two logs to the tool. Mask public IPs / SNMP strings first if needed.)

---

## The evidence model (why this tool is trustworthy)

Genie-style tools tell you *what* changed. The value here is the **why** and
**how to fix** — and, crucially, **how confident** each of those is. Every
finding shows:

- a **SOURCE** — `Design Guide`, `Protocol Logic`, `Bug List`, `Release Notes`, or `Config Diff`; and
- one of two **stamps**:
  - **VERIFIED BY DESIGN** — a protocol/design-guide fact or a plain config diff. Deterministic; safe to rely on. (e.g. the MTU math from RFC 7348, a config line that is present in *pre* and missing in *post*.)
  - **VERIFY REQUIRED** — anything that depends on a specific release/platform behaviour. The tool flags it and points you at the **Cisco Bug Search Tool / target-release notes** — it never states a version-specific cause as fact.

This is deliberate: a diff engine can *deduce* and *correlate*, but it must not
*guess* that "release X resets MTU" and present it as truth. Findings that would
be that kind of claim are always marked **VERIFY REQUIRED**.

### Two kinds of fix

- **DETERMINISTIC — PASTE-READY**: for config loss/change, the fix is the removed line itself. The tool hands you the exact config to paste back (e.g. `interface Eth1/49 → mtu 9216`).
- **INVESTIGATE**: for control-plane / operational symptoms (a downed IS-IS adjacency, an Idle BGP session, a lost NVE peer), the root cause needs judgement — the tool gives you the likely cause and the commands to verify on the device, but does not auto-remediate.

### Correlation

When several symptoms line up (e.g. MTU reset → IS-IS adjacency down → BGP
session down → NVE peer lost), the tool adds a **ROOT CAUSE** card that ties them
into one chain and points at the single fix most likely to recover the rest.

---

## Commands understood

**Specialised analysis** (severity + why + fix + correlation):
`show running-config` (per-interface drift, MTU-vs-VXLAN rule), `show isis adjacency`,
`show bgp vrf all all summary`, `show nve peers`, `show interface status`.

**Diff + basic classification:**
`show ip route`, `show ip route vrf all`, `show vpc`, `show module`,
`show ip interface brief`, `show mac address-table`, `show ip arp`,
`show interface description`, `show lldp neighbors`, `show isis database detail`.

**Informational / expected:** `show version`, `show boot`, `show inventory`.
**Ignored** (always changes): `show clock`.

Anything not specialised still gets a clean, accurate line-diff, so the tool
never silently drops a command you pasted.

---

## Hosting on GitHub Pages

1. Create a repo (e.g. `driftwatch`) and add `index.html` (plus this README and the sample files).
2. Repo **Settings → Pages → Build and deployment → Source: Deploy from a branch**, pick `main` / root.
3. Open the published URL on any laptop (including a corporate Windows laptop) — it's a single static page, so it needs no server, no Python, no install.

Because everything runs client-side, the sample demo works on GitHub Pages as-is.
For your **real** captures the same is true — the text you paste is processed in
the browser and never sent anywhere.

---

## Scope & honesty (for the manager conversation)

- The **diff engine** here is a prototype in JavaScript. It parses the command
  set above; for the highest-value commands it adds real engineering analysis,
  and every other command gets an accurate diff.
- In **production (Step 2)**, the parsing is done by **Cisco pyATS/Genie** — a
  free, Cisco-maintained framework with 2700+ parsers — behind a small internal
  service. This same page and evidence model sit on top. We are **not**
  rebuilding Genie; we are adding the layer Genie doesn't provide: the *why*, the
  *fix*, and the *verification provenance*.
- **Nothing is applied automatically.** The tool is an advisor; the engineer
  reviews each finding, confirms the **VERIFY REQUIRED** items against Cisco
  documentation and the live device, and signs off.

---

## Files

| File | What it is |
|------|------------|
| `index.html` | The dashboard — self-contained (engine embedded), open or host as-is. |
| `engine.js` | The readable source of the comparison engine (same logic embedded in `index.html`). |
| `sample_pre.txt` / `sample_post.txt` | Example captures showing the expected input format (the MTU-cascade demo). |
