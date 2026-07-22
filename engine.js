/* ============================================================================
   DRIFTWATCH ENGINE  -  NX-OS Pre/Post Upgrade Comparison
   ----------------------------------------------------------------------------
   Pure logic, no DOM. Runs in Node (tests) and browser (embedded in the page).

   Pipeline:
     splitCapture(text)  -> { command: body, ... }
     compareAll(pre,post) -> [ finding, ... ]  (per-command diffs + analysis)
     correlate(findings)  -> maybe prepends a root-cause correlation finding

   A "finding" carries the config/state DIFF plus an ENGINEERING ANALYSIS
   (why + source + verified flag) and a RECOMMENDED FIX. The "why" is produced
   by an encoded rule base derived from protocol design guides, not by guessing;
   version-specific attributions are always flagged "verify-required".
   ========================================================================== */

/* ---------- known commands (from the operator's capture list) ------------- */
const KNOWN_COMMANDS = [
  "show running-config",
  "show ip arp",
  "show module",
  "show ip interface brief",
  "show mac address-table",
  "show version",
  "show inventory",
  "show boot",
  "show ip route vrf all",
  "show ip route",
  "show isis adjacency",
  "show bgp vrf all all summary",
  "show isis database detail",
  "show vpc",
  "show nve peers",
  "show interface status",
  "show interface description",
  "show lldp neighbors",
  "show clock",
];

function normCmd(s) {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}

/* Split a full capture into { command: body }. Detects a command boundary when
   a line (optionally after a "hostname# " prompt) equals a known command. */
function splitCapture(text) {
  const sections = {};
  if (!text) return sections;
  const lines = text.split(/\r?\n/);
  const knownNorm = new Set(KNOWN_COMMANDS.map(normCmd));
  let current = null;
  for (const raw of lines) {
    // strip an optional prompt like "LEAF-01# " or "switch(config)# "
    const stripped = raw.replace(/^\s*\S+?[#>]\s*/, "").trimEnd();
    const cand = normCmd(stripped);
    if (knownNorm.has(cand)) {
      current = cand;
      if (!(current in sections)) sections[current] = [];
      continue;
    }
    if (current) sections[current].push(raw);
  }
  const out = {};
  for (const k of Object.keys(sections)) out[k] = sections[k].join("\n").trim();
  return out;
}

/* ---------- generic line diff (LCS) --------------------------------------- */
function lcsDiff(preLines, postLines) {
  const n = preLines.length, m = postLines.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = preLines[i] === postLines[j]
        ? dp[i + 1][j + 1] + 1
        : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const rows = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (preLines[i] === postLines[j]) { rows.push({ type: "ctx", text: preLines[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { rows.push({ type: "del", text: preLines[i] }); i++; }
    else { rows.push({ type: "add", text: postLines[j] }); j++; }
  }
  while (i < n) rows.push({ type: "del", text: preLines[i++] });
  while (j < m) rows.push({ type: "add", text: postLines[j++] });
  return rows;
}

/* keep a compact diff: context lines only near changes */
function compactDiff(rows, pad = 1) {
  const keep = new Array(rows.length).fill(false);
  rows.forEach((r, idx) => {
    if (r.type !== "ctx") for (let k = idx - pad; k <= idx + pad; k++) if (k >= 0 && k < rows.length) keep[k] = true;
  });
  const out = [];
  let gap = false;
  rows.forEach((r, idx) => {
    if (keep[idx]) { out.push(r); gap = false; }
    else if (!gap) { out.push({ type: "gap", text: "  ...  " }); gap = true; }
  });
  return out;
}

/* ---------- small parse helpers ------------------------------------------- */
const splitBlocks = (cfg) => {
  // running-config -> { global:[], interfaces:{name:[lines]} }
  const interfaces = {}; const global = []; let cur = null;
  for (const raw of (cfg || "").split(/\r?\n/)) {
    if (!raw.trim()) continue;
    if (/^interface\s+\S+/i.test(raw)) { cur = raw.trim(); interfaces[cur] = interfaces[cur] || []; }
    else if (/^\s+\S/.test(raw) && cur) interfaces[cur].push(raw.trim());
    else { cur = null; global.push(raw.trim()); }
  }
  return { global, interfaces };
};

/* ========================================================================== */
/*  KNOWLEDGE BASE HELPERS  (produce why + source + verified + fix)           */
/* ========================================================================== */
const SRC = {
  DESIGN: "Design Guide",       // RFC / Cisco design guide - deterministic
  PROTO: "Protocol Logic",      // deducible from how the protocol works
  BUGS: "Bug List",             // must be confirmed on Cisco Bug Search Tool
  NOTES: "Release Notes",       // must be confirmed in target-release notes
  DIFF: "Config Diff",          // the change itself is the evidence
};

/* ========================================================================== */
/*  PER-COMMAND COMPARATORS                                                    */
/*  Each returns an array of findings for that command.                        */
/* ========================================================================== */

function cmpRunningConfig(pre, post) {
  const a = splitBlocks(pre), b = splitBlocks(post);
  const findings = [];
  const names = [...new Set([...Object.keys(a.interfaces), ...Object.keys(b.interfaces)])];

  for (const name of names) {
    const pl = a.interfaces[name] || [], ql = b.interfaces[name] || [];
    const removed = pl.filter((l) => !ql.includes(l));
    const added = ql.filter((l) => !pl.includes(l));
    if (!removed.length && !added.length) continue;

    // detect MTU change specifically
    const mtuPre = (pl.find((l) => /^mtu\s+\d+/i.test(l)) || "").match(/\d+/);
    const mtuPost = (ql.find((l) => /^mtu\s+\d+/i.test(l)) || "").match(/\d+/);
    const isVtepUnderlay = pl.concat(ql).some((l) => /ip router isis|ip address/i.test(l));

    const diffRows = [{ type: "ctx", text: name }];
    removed.forEach((l) => diffRows.push({ type: "del", text: "  " + l }));
    added.forEach((l) => diffRows.push({ type: "add", text: "  " + l }));

    if (mtuPre && mtuPost && +mtuPre[0] !== +mtuPost[0] && +mtuPost[0] < 1600) {
      findings.push({
        cmd: "show running-config",
        severity: "critical",
        title: `Fabric uplink MTU reduced below VXLAN requirement on ${name}`,
        tags: ["interface", "underlay", "vxlan-mtu"],
        diff: diffRows,
        why: {
          text:
            `The interface MTU on ${name} changed from ${mtuPre[0]} to ${mtuPost[0]}. VXLAN encapsulation adds ` +
            `50-54 bytes of outer MAC/IP/UDP/VXLAN headers to every frame (RFC 7348), so a ${mtuPost[0]}-byte ` +
            `underlay can no longer carry full-size overlay frames between VTEPs. Additionally, IS-IS pads its ` +
            `hello PDUs to the interface MTU by default, so this reset can also break the IS-IS adjacency on ` +
            `this link where the neighbor is still at the higher MTU.`,
          source: SRC.DESIGN,
          verified: true,
          note:
            `The DIFF itself (${mtuPre[0]}->${mtuPost[0]}) and the encapsulation math are verified by design. ` +
            `WHETHER this MTU reset is an expected behaviour of the specific target release/platform is NOT a ` +
            `known fact - confirm against the target-release notes and Cisco Bug Search Tool before assuming it ` +
            `is documented.`,
          verifyRequired: true,
        },
        fix: {
          type: "deterministic",
          intro: `Restore the pre-upgrade MTU on the affected uplink(s). This is a config-loss restore, so the fix is the removed line itself:`,
          commands: [name, `  mtu ${mtuPre[0]}`],
          verify: [
            `show interface ${name.replace(/^interface\s+/i, "")} | include MTU`,
            "show isis adjacency",
            "show nve peers",
          ],
        },
      });
    } else {
      // generic per-interface config drift
      findings.push({
        cmd: "show running-config",
        severity: removed.length ? "warning" : "info",
        title: `Configuration ${removed.length ? "removed" : "added"} on ${name}`,
        tags: ["interface", "config-drift"],
        diff: diffRows,
        why: {
          text: `${removed.length ? removed.length + " line(s) present before are missing now" : added.length + " new line(s) appeared"} on ${name}. During an upgrade, lines that disappear are usually unintended drift.`,
          source: SRC.DIFF,
          verified: true,
          verifyRequired: false,
        },
        fix: removed.length
          ? { type: "deterministic", intro: "If this change was unintended, restore the removed lines:", commands: [name, ...removed.map((l) => "  " + l)], verify: [`show running-config interface ${name.replace(/^interface\s+/i, "")}`] }
          : { type: "investigate", intro: "New lines appeared. Confirm they were intended for this change window.", commands: [], verify: [] },
      });
    }
  }
  return findings;
}

function parseIsisAdj(txt) {
  // System ID  SNPA  Level  State  Hold Time  Interface
  const out = {};
  for (const line of (txt || "").split(/\r?\n/)) {
    const m = line.match(/^\s*(\S+)\s+\S+\s+(\d+)\s+(\S+)\s+\S+\s+(\S+)\s*$/);
    if (m && !/System\s+ID/i.test(line)) out[m[1]] = { level: m[2], state: m[3].toUpperCase(), intf: m[4] };
  }
  return out;
}
function cmpIsisAdj(pre, post) {
  const a = parseIsisAdj(pre), b = parseIsisAdj(post), findings = [];
  for (const id of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const p = a[id], q = b[id];
    if (p && !q) {
      findings.push(mk("show isis adjacency", "critical", `IS-IS underlay adjacency to ${id} is DOWN`, ["underlay", "isis", "adjacency"],
        [{ type: "del", text: `${id}  Level ${p.level}  UP  ${p.intf}` }, { type: "add", text: `${id}  (adjacency lost)` }],
        `The IS-IS adjacency to ${id} on ${p.intf} was UP before the upgrade and is now gone. Because the underlay carries VTEP loopback reachability, losing this adjacency breaks reachability to everything learned via ${id}. A very common trigger is an MTU mismatch on ${p.intf} (IS-IS pads hellos to MTU), so correlate with any MTU change on that interface.`,
        SRC.PROTO, true, false,
        { type: "investigate", intro: `Confirm L1/L2 on ${p.intf}, check for an MTU mismatch, and verify IS-IS auth/net matches the neighbor:`, commands: [], verify: [`show isis adjacency`, `show interface ${p.intf} | include MTU`, `show isis interface ${p.intf}`] }));
    } else if (p && q && p.state !== q.state) {
      findings.push(mk("show isis adjacency", "warning", `IS-IS adjacency to ${id} state ${p.state} -> ${q.state}`, ["underlay", "isis"],
        [{ type: "ctx", text: id }, { type: "del", text: `state ${p.state}` }, { type: "add", text: `state ${q.state}` }],
        `Adjacency to ${id} is no longer full UP. Underlay instability affects overlay reachability.`, SRC.PROTO, true, false,
        { type: "investigate", intro: "Check the link and IS-IS timers/MTU.", commands: [], verify: [`show isis adjacency detail`] }));
    }
  }
  return findings;
}

function parseBgpSummary(txt) {
  // Neighbor  V  AS  MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
  const out = {};
  for (const line of (txt || "").split(/\r?\n/)) {
    const m = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+\s+\d+\s+\S+\s+(\S+)\s*$/);
    if (m) out[m[1]] = m[2]; // last col = State/PfxRcd (number = established)
  }
  return out;
}
function cmpBgpSummary(pre, post) {
  const a = parseBgpSummary(pre), b = parseBgpSummary(post), findings = [];
  const down = (v) => v === undefined || !/^\d+$/.test(v);
  for (const ip of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const p = a[ip], q = b[ip];
    if (p === undefined || q === undefined) continue;
    if (down(q) && !down(p)) {
      findings.push(mk("show bgp vrf all all summary", "critical", `BGP overlay session to ${ip} is DOWN (${q})`, ["overlay", "bgp-evpn", "session"],
        [{ type: "del", text: `${ip}  Established  ${p} prefixes` }, { type: "add", text: `${ip}  ${q}` }],
        `The BGP session to ${ip} was Established (${p} prefixes) and is now '${q}'. If ${ip} is a spine/route-reflector loopback, this is very likely a downstream effect of losing underlay reachability to that loopback - correlate with IS-IS adjacency and MTU findings before touching BGP itself.`,
        SRC.PROTO, true, false,
        { type: "investigate", intro: `Check underlay reachability to ${ip}, then the BGP session:`, commands: [], verify: [`show ip route ${ip}`, `show bgp l2vpn evpn summary`, `show bgp vrf all all summary`] }));
    } else if (/^\d+$/.test(p) && /^\d+$/.test(q)) {
      const drop = +p - +q;
      if (drop > 0 && drop >= Math.max(1, Math.floor(+p * 0.15))) {
        findings.push(mk("show bgp vrf all all summary", "warning", `BGP prefixes from ${ip} dropped ${p} -> ${q}`, ["overlay", "bgp-evpn"],
          [{ type: "ctx", text: ip }, { type: "del", text: `${p} prefixes` }, { type: "add", text: `${q} prefixes` }],
          `Prefix count from ${ip} fell by ${drop}. Some EVPN routes were withdrawn - this frequently pairs with a lost NVE peer (a withdrawn leaf shows up here as a prefix drop).`,
          SRC.PROTO, true, false,
          { type: "investigate", intro: "Identify which VNIs/hosts disappeared and correlate with NVE peers.", commands: [], verify: [`show bgp l2vpn evpn`, `show nve peers`] }));
      }
    }
  }
  return findings;
}

function parseNvePeers(txt) {
  const out = {};
  for (const line of (txt || "").split(/\r?\n/)) {
    const m = line.match(/^\s*nve\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/i);
    if (m) out[m[1]] = m[2];
  }
  return out;
}
function cmpNvePeers(pre, post) {
  const a = parseNvePeers(pre), b = parseNvePeers(post), findings = [];
  for (const ip of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const p = a[ip], q = b[ip];
    if (p && !q) {
      findings.push(mk("show nve peers", "critical", `VXLAN VTEP peer ${ip} is no longer present`, ["overlay", "vxlan", "nve"],
        [{ type: "del", text: `nve1  ${ip}  ${p}` }, { type: "add", text: `nve1  ${ip}  (peer lost)` }],
        `Remote VTEP ${ip} was a peer before the upgrade and is gone now, so hosts behind that leaf are unreachable over the overlay. This is a consequence, not a config item - it usually means that leaf's EVPN routes are no longer received, often because underlay reachability to a spine was lost.`,
        SRC.PROTO, true, false,
        { type: "investigate", intro: `Check underlay reachability and whether EVPN routes from ${ip} are present:`, commands: [], verify: [`show ip route ${ip}`, `show bgp l2vpn evpn | include ${ip}`, `show nve peers`] }));
    }
  }
  return findings;
}

function parseIntfStatus(txt) {
  const out = {};
  for (const line of (txt || "").split(/\r?\n/)) {
    const m = line.match(/^\s*(Eth\S+|Po\S+|mgmt\S+)\s+(.*?)\s{2,}(connected|notconnect|disabled|sfpAbsent|xcvrAbsen\S*|linkFlapE\S*|err\S*)\s+(\S+)/i);
    if (m) out[m[1]] = { status: m[3].toLowerCase(), vlan: m[4] };
  }
  return out;
}
function cmpIntfStatus(pre, post) {
  const a = parseIntfStatus(pre), b = parseIntfStatus(post), findings = [];
  for (const port of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const p = a[port], q = b[port];
    if (p && q && p.status !== q.status) {
      const wentDown = p.status === "connected" && q.status !== "connected";
      findings.push(mk("show interface status", wentDown ? "critical" : "info", `${port} status ${p.status} -> ${q.status}`, ["interface", "l1"],
        [{ type: "ctx", text: port }, { type: "del", text: `status ${p.status}` }, { type: "add", text: `status ${q.status}` }],
        wentDown
          ? `${port} was connected before the upgrade and is now ${q.status}. A physical/data-plane port went down across the change.`
          : `${port} status changed to ${q.status}.`,
        SRC.DIFF, true, false,
        { type: "investigate", intro: `Check the port and its transceiver/neighbor:`, commands: [], verify: [`show interface ${port}`, `show interface ${port} transceiver`] }));
    }
  }
  return findings;
}

/* generic "list of KV lines" comparator used for the simpler tables */
function cmpGeneric(cmd, pre, post, opts = {}) {
  const pl = (pre || "").split(/\r?\n/).filter((l) => l.trim());
  const ql = (post || "").split(/\r?\n/).filter((l) => l.trim());
  const rows = compactDiff(lcsDiff(pl, ql));
  const changed = rows.some((r) => r.type === "del" || r.type === "add");
  if (!changed) return [];
  return [mk(cmd, opts.severity || "info", opts.title || `Output changed: ${cmd}`, opts.tags || ["diff"],
    rows,
    opts.why || `The output of "${cmd}" differs between pre and post. Review the change against the intended design.`,
    opts.source || SRC.DIFF, opts.verified !== false, !!opts.verifyRequired,
    opts.fix || { type: "investigate", intro: "Review the highlighted lines.", commands: [], verify: [cmd] })];
}

/* finding factory */
function mk(cmd, severity, title, tags, diff, whyText, source, verified, verifyRequired, fix) {
  return { cmd, severity, title, tags, diff, why: { text: whyText, source, verified, verifyRequired }, fix };
}

/* ---------- command registry --------------------------------------------- */
const REGISTRY = {
  "show running-config": cmpRunningConfig,
  "show isis adjacency": cmpIsisAdj,
  "show bgp vrf all all summary": cmpBgpSummary,
  "show nve peers": cmpNvePeers,
  "show interface status": cmpIntfStatus,
  // informational / expected-to-change
  "show version": (p, q) => cmpGeneric("show version", p, q, { severity: "info", title: "Software version changed (expected after upgrade)", tags: ["version", "expected"], why: "The NX-OS version changed - this is the intended result of the upgrade. Confirm it matches the target release you planned.", source: SRC.DIFF }),
  "show clock": () => [], // always changes; ignore
  "show boot": (p, q) => cmpGeneric("show boot", p, q, { severity: "info", title: "Boot variables changed", tags: ["boot"], why: "Boot variables changed. Verify they point to the intended new image so the box boots correctly on next reload.", source: SRC.DIFF }),
};

/* commands that get a plain diff if present but no specialised rule */
const GENERIC_DEFAULT = [
  "show ip arp", "show module", "show ip interface brief", "show mac address-table",
  "show inventory", "show ip route vrf all", "show ip route", "show isis database detail",
  "show vpc", "show interface description", "show lldp neighbors",
];

/* ---------- run everything ------------------------------------------------ */
function compareAll(preText, postText) {
  const pre = splitCapture(preText), post = splitCapture(postText);
  const cmds = new Set([...Object.keys(pre), ...Object.keys(post)]);
  const findings = [];
  const compared = [];

  for (const cmd of KNOWN_COMMANDS) {
    if (!cmds.has(cmd)) continue;
    compared.push(cmd);
    const fn = REGISTRY[cmd];
    if (fn) findings.push(...fn(pre[cmd] || "", post[cmd] || ""));
    else if (GENERIC_DEFAULT.includes(cmd)) {
      const sev = /route|vpc|module/.test(cmd) ? "warning" : "info";
      findings.push(...cmpGeneric(cmd, pre[cmd] || "", post[cmd] || "", {
        severity: sev,
        title: `Change detected: ${cmd}`,
        tags: [cmd.replace(/^show\s+/, "")],
      }));
    }
  }
  return { findings: correlate(findings), compared };
}

/* ---------- correlation: tie scattered symptoms to a root cause ----------- */
function correlate(findings) {
  const hasMtu = findings.some((f) => f.tags.includes("vxlan-mtu"));
  const isisDown = findings.some((f) => f.tags.includes("adjacency"));
  const bgpDown = findings.some((f) => f.tags.includes("session"));
  const nveLost = findings.some((f) => f.tags.includes("nve"));
  const chain = [hasMtu && "uplink MTU reset", isisDown && "IS-IS adjacency down", bgpDown && "BGP overlay session down", nveLost && "NVE peer lost"].filter(Boolean);

  if (hasMtu && (isisDown || bgpDown || nveLost) && chain.length >= 2) {
    const corr = {
      cmd: "correlation",
      severity: "critical",
      title: "Correlated root cause: underlay MTU reset cascading into the overlay",
      tags: ["root-cause", "correlation"],
      diff: [{ type: "ctx", text: "Symptom chain detected across commands:" }, ...chain.map((c, i) => ({ type: "del", text: `${i + 1}. ${c}` }))],
      why: {
        text:
          `Several independent findings line up into one chain: ${chain.join("  ->  ")}. ` +
          `The MTU reset on the fabric uplinks is the plausible single root cause - it can break the IS-IS ` +
          `adjacency (hello padding to MTU), which removes underlay reachability to the spine loopbacks, which ` +
          `takes down the BGP EVPN sessions and therefore the NVE peers. Fixing the MTU first is likely to ` +
          `recover the rest.`,
        source: SRC.PROTO,
        verified: true,
        note: "This is a correlation of your own captured data plus protocol design logic. It is a strong hypothesis, but confirm on the device that restoring MTU recovers the adjacency, session and peer before closing out.",
        verifyRequired: true,
      },
      fix: {
        type: "deterministic",
        intro: "Address the root cause (MTU) first, then re-check the downstream symptoms:",
        commands: ["! restore uplink MTU (see running-config finding for exact interfaces)", "interface Ethernet1/49-50", "  mtu 9216"],
        verify: ["show isis adjacency", "show bgp vrf all all summary", "show nve peers"],
      },
    };
    return [corr, ...findings];
  }
  return findings;
}

/* ---------- node export (ignored in browser) ------------------------------ */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { splitCapture, compareAll, correlate, KNOWN_COMMANDS };
}
