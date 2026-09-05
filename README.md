# domainblock — reverse-DNS pattern blocker for MikroTik

Blocks inbound IPs whose **reverse-DNS (PTR)** hostname matches a pattern you
control (e.g. `*.googleusercontent.com`). The router queues new inbound source
IPs; a small Ruby script on your Linux box looks up each one, matches it against
your pattern list, and writes matches to a MikroTik address-list that a drop
rule uses. Matched IPs are blocked from **everything except your VPN ports**, so
you can never lock yourself out of remote access.

The script also keeps the forward/DSTNAT queue rule's watched-port list in sync
with the services you deliberately forward (see **Watched-ports auto-management**
below), so you don't hand-edit ports as you add or remove port-forwards.

Bans are cached to disk and survive both router reboots and script restarts (see
**Ban-cache persistence** below) — the MikroTik's dynamic address-list is wiped
on restart, so without the cache a scheduled reboot would empty your ban list.

Optionally, the script can also ban by **ASN / hosting-provider name** (see
**Optional: block by datacenter/ASN too** below) — a second signal for
datacenter IPs that have no PTR record at all, which reverse-DNS matching
structurally cannot see.

An optional monthly report (see **Monthly pattern-coverage report** below)
diffs what actually hit you against your current pattern files and emails
what's not yet covered — including a persistence check across everything
logrotate is still keeping, which is what catches a source that paces its
attempts specifically to avoid ranking high in any single month.

No Docker, no CrowdSec, no gems — the script talks the RouterOS API directly
using only Ruby's standard library. Everything lives self-contained in one
install directory.

---

## How it works

```
new inbound IP -> router adds it to "domainblock-check" (1 min timeout)
                     |
   Ruby script (every 30s) reads that list, does a reverse-DNS lookup,
   matches hostname against domainblock-patterns.txt
                     |
   match -> script adds IP to "domainblock-banned" on the router
                     |
   router drop rule blocks "domainblock-banned" (all ports except VPN)
```

The router does the enforcement; the script only decides membership. If the
Linux box is down, the script simply stops adding new bans — existing bans
expire on their own timeout, and nothing on the router breaks. **Fail-open.**
Bans that existed before a router reboot are restored from the on-disk cache on
the next refresh run (see section 1f), so a scheduled reboot doesn't permanently
lose them.

Legitimate users are never on `domainblock-banned`, so they never match the
block rules at all — the rules are inert until the script bans something.

> **Where your services live matters — read this before you configure.**
> The recorder that feeds detection is an `add-src-to-address-list` rule. A rule
> in the **input** chain only sees traffic that terminates **on the router
> itself**. Services that run on another box (Home Assistant on a separate host,
> a NAS, etc.) are reached via **DSTNAT port-forwarding**, and that traffic
> traverses the **forward** chain, never input. So you need a queue rule in the
> **forward** chain for anything DSTNAT'd behind the router, and (only if you
> host something on the router itself) one in **input**. If you only add the
> input queue rule, scanners hitting your forwarded services are never recorded,
> never looked up, and never banned — even though the pattern would have matched.
> This was the original "blocked domains still get through" bug. Section 1c adds
> both rules; most home setups end up using the **forward** one exclusively.

---

## Files (all in one folder)

```
domainblock.rb                the script (reads config + patterns from its own dir)
domainblock-monthly-report.rb optional: emails a monthly pattern-coverage report (monthly_report: true)
config.yml                    router IP, credentials, list names, timeouts, watched-ports + ban-cache opts
domainblock-patterns.txt      your PTR block patterns — the thing you edit
domainblock-asn-patterns.txt  your ASN/datacenter block patterns (optional, asn_check: true)
ban-cache.txt                 auto-generated: banned IPs snapshot (survives reboots); do not edit while running
seen.csv                      auto-generated if seen_log: true; logrotate (installed by install.sh) rolls
                              it into seen.csv-YYYY-MM[.gz] monthly, 6 kept
install.sh                    sets up the systemd services + timers + logrotate drop-in
uninstall.sh                  removes them
README.md                     this file
```

The script resolves `config.yml` and `domainblock-patterns.txt` from its own
directory, so the folder works wherever it lives. **Put it under `/opt`, not in
a home directory** — see the permissions note in section 2.

---

## 1. Router setup (MikroTik / RouterOS 7.x)

### 1a. API user

```
/user group add name=domainblock policy=read,write,api,!ftp,!local,!ssh,!reboot,!policy,!test,!password,!sniff,!romon,!rest-api
/user add name=domainblock group=domainblock password=STRONG_PASSWORD
```

`read,write,api` are all required: `read` to list address-lists and the NAT/filter
tables, `write` to add bans and to update the forward queue rule's `dst-port`
(watched-ports auto-management), `api` for the connection itself.

### 1b. Enable + restrict the API to your Linux box

```
/ip service set api address=<HA_LINUX_IP>/32 disabled=no
# confirm:
/ip service print where name=api
```

(Plain API on 8728 sends the password in the clear over your LAN. For TLS, use `api-ssl` on 8729 and set `router_port: 8729` + `router_tls: true` in config.yml.)

### 1c. Add the rules

> **The `#domainblock` tag is load-bearing.** Every rule below carries
> `#domainblock` in its comment. The script discovers the rules it manages by
> this tag, and you use it to filter the rule list in Winbox/WebFig
> (`Comment contains #domainblock`). Do not drop the tag when you edit a comment.

> **Lesson learned during install:** `place-before=[find where comment~"..."]`
> repeatedly failed with *"invalid internal item number" / "no such item"*
> because the `~` regex chokes on special characters in RouterOS comments
> (commas, double spaces). **Add every rule plain, then position it with `move`
> by number.** Exact-match `find` (`comment="..."` with `=`) works for `move`;
> the regex `~` at add-time does not.

Add all seven rules (they append at the bottom — that's fine, we move the
order-sensitive ones next):

```
/ip firewall filter add chain=input action=add-src-to-address-list address-list=domainblock-check address-list-timeout=1m in-interface-list=WAN connection-state=new protocol=tcp dst-port=<router-terminated-ports> comment="#domainblock: queue new inbound for PTR check"
/ip firewall filter add chain=forward action=add-src-to-address-list address-list=domainblock-check address-list-timeout=1m in-interface-list=WAN connection-state=new connection-nat-state=dstnat protocol=tcp comment="#domainblock: queue new inbound (forward/DSTNAT) for PTR check"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=udp dst-port=13231-13239,1194,1701,500,4500 comment="#domainblock: allow WG/OpenVPN/L2TP even if banned"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=tcp dst-port=1723,8291 comment="#domainblock: allow PPTP/Winbox even if banned"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=gre comment="#domainblock: allow PPTP GRE even if banned"
/ip firewall filter add chain=input action=drop src-address-list=domainblock-banned in-interface-list=WAN comment="#domainblock: drop matched IPs (input)"
/ip firewall filter add chain=forward action=drop src-address-list=domainblock-banned in-interface-list=WAN comment="#domainblock: drop matched IPs (forward)"
```

**About the two queue rules:**

- The **input** queue rule records scanners that hit a service **terminating on
  the router itself** — anything you expose with an `input action=accept` rule.
  Set its `dst-port` to exactly those ports. If nothing terminates on the router
  (common — everything is port-forwarded to other hosts), **disable this rule**;
  it will simply match nothing. The script does **not** manage this rule.
- The **forward** queue rule records scanners that hit a service **DSTNAT'd to
  another host**. Add it with **no `dst-port`** initially; the script fills in
  the `dst-port` automatically from your tagged NAT rules (see Watched-ports).
  Match on `connection-nat-state=dstnat` — this is what distinguishes forwarded
  traffic. The script **manages this rule's `dst-port`**.

Neither queue rule blocks anything (`add-src-to-address-list` only records), so
their position in the chain doesn't matter. Only the VPN-accepts and the two
drops are order-sensitive.

### 1d. Position the order-sensitive rules with `move`

Print the chains to get current numbers:

```
/ip firewall filter print where chain=input
/ip firewall filter print where chain=forward
```

Then move by number (`move <rule#> destination=<target#>` places the rule *before* the target). Target ordering:

**Input chain**, top to bottom:

1. (your existing top-of-chain drop, if any, e.g. `Blocked-External`)
2. domainblock VPN-accept — UDP (WG/OpenVPN/L2TP)
3. domainblock VPN-accept — TCP (PPTP/Winbox)
4. domainblock VPN-accept — GRE
5. domainblock input drop
6. …then your service accepts, `accept established,related`, etc.

> **Critical placement detail:** the input drop must sit **above your
> per-service accept rules**, not merely above `accept established,related`. If
> it sat below them, a banned IP hitting one of those service ports would be
> accepted before reaching the drop. The three VPN-accepts go immediately above
> the drop so the carve-out is evaluated first.

**Forward chain:** the domainblock forward drop goes **above** `defconf: drop all from WAN not DSTNATed`.

> **Note on the forward drop and `established,related`:** most configs have
> `defconf: accept established,related` high in the forward chain, above the
> domainblock forward drop. That's fine — a banned IP's **new** connections
> still hit the drop. The only residue is that a single connection opened during
> the up-to-one-interval reactive window rides `established,related` until it
> closes. For scanner traffic that's harmless, so leave the forward drop where
> the target ordering puts it rather than moving it above the established-accept
> (moving it risks tearing down legitimate forwarded sessions on every ban).

---

## 1e. Watched-ports auto-management (the `#domainblock` NAT tag)

This is what keeps the **forward** queue rule's `dst-port` list correct without
you editing it by hand.

**The idea:** you tag the NAT `dst-nat` rules you want PTR-watched with
`#domainblock` in their comment. On every run the script reads the NAT table,
collects the watched ports from those tagged rules, and writes them onto the
forward queue rule's `dst-port`. Add a new port-forward and tag it → it's watched
on the next run. Untag or disable it → it drops off. Dynamic UPnP/NAT-PMP
mappings (e.g. a torrent client's listen port) are **skipped automatically**
because they carry the `dynamic` flag — so peer traffic never floods the
candidate list.

**Tag your intentional forwards:**

```
# add "#domainblock" anywhere in the comment of each dst-nat rule to watch
/ip firewall nat set <rule#> comment="redirect to HomeAssistant, watched with #domainblock"
```

**Which port gets watched — read `to-ports`, not `dst-port`.** The forward chain
sees the packet **after** DSTNAT translation, so the port the queue rule must
match is the **internal** port. The script therefore takes each tagged rule's
`to-ports`, falling back to `dst-port` only when `to-ports` is empty (port not
translated). Example: a rule `dst-port=443 ... to-ports=8123` contributes **8123**,
not 443. This is the single most important detail in the whole mechanism; get it
backwards and the queue silently matches nothing.

**Rules the script applies when deriving the watched set:**
- `chain=dstnat`, `action=dst-nat`
- **not** `disabled`
- **not** `dynamic` (this is what excludes UPnP/torrent mappings)
- comment contains `#domainblock`
- port = `to-ports` (fallback `dst-port`), comma-lists split, whole set deduped

**The forward queue rule this writes to** is found by: `chain=forward`,
`action=add-src-to-address-list`, comment contains `#domainblock`.

> ### ⚠️ Trap: never put a `dst-address-list` (or any extra match) on the forward queue rule
>
> The script manages **only** the `dst-port` of the forward queue rule. It does
> not know about, and will never remove, any other match condition you add. If
> you put a `dst-address-list=` (or `dst-address=`, `src-address=`, …) on the
> rule, RouterOS **ANDs** it with the port match. If that address-list is empty
> or doesn't match, the rule matches **nothing** — the port list looks correct
> but no traffic is ever queued, and blocked domains silently get through again.
>
> This bit us once: an abandoned "watch by internal host" experiment left a
> `dst-address-list=domainblock-watched` on the rule pointing at an empty list.
> The `dst-port` the script wrote was right, but the empty-list AND killed every
> match, and the forward path was dead until we stripped it.
>
> **The forward queue rule must match on exactly these, and nothing else:**
> ```
> chain=forward
> action=add-src-to-address-list
> address-list=domainblock-check
> address-list-timeout=1m
> in-interface-list=WAN
> connection-state=new
> connection-nat-state=dstnat
> protocol=tcp
> dst-port=<script-managed>        <- the ONLY field the script writes
> ```
> If you ever see `dst-address-list` (or another stray match) on it, remove it:
> ```
> /ip firewall filter set [find chain=forward action=add-src-to-address-list comment~"#domainblock"] !dst-address-list
> ```
> and confirm forward traffic is queuing again by watching the rule's counter
> climb (`/ip firewall filter print stats where chain=forward action=add-src-to-address-list comment~"#domainblock"`).

---

## 1f. Ban-cache persistence (surviving reboots)

MikroTik `domainblock-banned` entries are **dynamic address-list entries with a
timeout** — they live in RAM and are **wiped on every router reboot**. If you run
a scheduled reboot (common on RouterOS, e.g. weekly), your ban list is emptied
each time and has to rebuild from scratch. The ban cache fixes this.

**How it works:** the script keeps a plain-text cache of the banned set on the
Linux box (`ban-cache.txt` in the script dir). The cache is the source of truth
and outlives both the router and the script:

- **Restore** — re-adds any cached IP that isn't currently on the router's banned
  list, with a **fresh** `ban_timeout` and its original matched-PTR comment. This
  refills the router after a reboot. Restore is **blind** — it trusts the cache
  and does not re-run the PTR lookup, so it's fast.
- **Persist** — rewrites the cache from the router's current banned list
  (atomic temp-file + rename). New bans are captured; IPs you manually unban drop
  out of the cache on the next persist.

**Ordering matters and is handled for you:** restore runs **before** the ban
pass, persist runs **after**. So a reboot-emptied router is refilled from cache
*before* the persist step reads the list — the cache is never overwritten with a
momentarily-empty post-reboot list.

**Throttled by a run counter** in `/tmp` so the cache work only happens every
Nth run (default 60 runs = 30 min), not every 30s. Because `/tmp` is cleared on a
**Linux** reboot, a missing counter is treated as "due now" — so the first run
after a ha-linux reboot (or a service restart) immediately restores from cache.
That covers both failure modes: router reboot **and** script restart.

**First run / fresh install:** if `ban-cache.txt` doesn't exist yet, the run is
forced due and the cache is **seeded from the router's current banned list**
immediately — no waiting for the counter. So the cache is populated from whatever
is already banned on the MikroTik the first time the script runs after install.

**Tradeoff to know:** after a *router* reboot, the ban list stays empty until the
next refresh comes due — up to `ban_cache_every × interval` (default 30 min).
For cloud-scanner traffic that gap is harmless (they get re-detected live
anyway). Lower `ban_cache_every` if you want a shorter refill window at the cost
of two extra API calls per refresh.

**What the cache does *not* store:** the attack **port**. The script only ever
reads source **IPs** from `domainblock-check` (the queue rules record the IP, not
the port). The port exists only in the firewall log line (`dblock-fwd …:8123`),
never in the address-list the script sees — so the cache holds IP + matched PTR,
never a port. IP+port together comes only from remote syslog of the queue rules;
IP+domain comes from the script. Neither source alone has all three.

Config keys (see section 2). To test:

```
DOMAINBLOCK_DEBUG=1 ruby /opt/mikrotik_blockdomain/domainblock.rb   # look for "ban-cache: ..." lines
cat /opt/mikrotik_blockdomain/ban-cache.txt                          # mirrors domainblock-banned

# simulate a router reboot (clear bans), then restore:
# on the router:  /ip firewall address-list remove [find list=domainblock-banned]
DOMAINBLOCK_DEBUG=1 ruby /opt/mikrotik_blockdomain/domainblock.rb    # -> "ban-cache: restored N IP(s) from cache"
```

> ### ⚠️ systemd hardening must allow the cache + counter writes
>
> The service writes two files: `ban-cache.txt` (in the script dir) and the run
> counter (default `/tmp/domainblock-run-counter`). A hardened unit will silently
> block both — the writes are rescued and, because stdout is buffered under
> systemd, produce no visible error. The service looks healthy while the cache
> never updates (symptom: `ban-cache.txt` frozen while the router's banned list
> grows). The generated unit **must** include:
> ```ini
> ProtectSystem=strict
> PrivateTmp=no
> ReadWritePaths=/opt/mikrotik_blockdomain /tmp
> ```
> and must **not** have `ReadOnlyPaths=/opt/mikrotik_blockdomain` (it contradicts
> ReadWritePaths). `PrivateTmp=no` is required if the counter is in `/tmp` —
> with `PrivateTmp=yes`, each run gets an isolated ephemeral `/tmp`, so the
> counter never persists and the cache never comes due. Verify:
> ```
> systemctl show domainblock.service -p ReadWritePaths -p PrivateTmp
> ```
> Also ensure the script dir + cache file are owned by the service user
> (`chown -R domainblock:domainblock /opt/mikrotik_blockdomain`) — the atomic
> write needs directory write permission, not just file.
DOMAINBLOCK_DEBUG=1 ruby /opt/domainblock/domainblock.rb   # look for "ban-cache: ..." lines
cat /opt/domainblock/ban-cache.txt                          # mirrors domainblock-banned

# simulate a router reboot (clear bans), then restore:
# on the router:  /ip firewall address-list remove [find list=domainblock-banned]
rm /tmp/domainblock-run-counter
DOMAINBLOCK_DEBUG=1 ruby /opt/domainblock/domainblock.rb    # -> "ban-cache: restored N IP(s) from cache"
```

---

## 2. Linux box setup

No dependencies — stock Ruby 3.x has everything (socket, resolv, yaml, openssl).

### Install location — use /opt, not your home directory

> **Lesson learned:** running the service from `/home/<user>/...` fails with
> `status=200/CHDIR — Changing to the requested working directory failed:
> Permission denied`, because home directories are mode 700 and the unprivileged
> `domainblock` service user can't traverse into them. Put the folder under `/opt`.

```
sudo mv ./mikrotik_blockdomain /opt/domainblock    # or copy the folder there
cd /opt/domainblock
```

(If you must keep it under a home dir, `sudo chmod 755 /home/<user>` makes the
directory traversable — but /opt is cleaner.)

### Configure

Edit `config.yml` — set `router_host`, `router_pass` (and for API-SSL:
`router_port: 8729` + `router_tls: true`). Watched-ports and ban-cache options:

```yaml
# --- ban length ---
ban_timeout: 10d                # how long a ban lasts; default 10 days

# --- watched-ports auto-management (forward queue rule dst-port sync) ---
watched_ports_manage: true      # default true; set false to leave the rule alone
exclude_ports: []               # ports to force-exclude even if a tagged NAT rule has them
                                # e.g. exclude_ports: [8124]

# --- ban-cache persistence (survive router reboots + script restarts) ---
ban_cache: true                             # default true
ban_cache_file: ban-cache.txt               # snapshot, relative to script dir
ban_cache_every: 60                         # refresh (restore+persist) every N runs; 60 @30s = 30 min
ban_cache_counter: /tmp/domainblock-run-counter   # cleared on Linux reboot => first run after reboot restores

# --- recon log: find NEW domains to ban ---
seen_log: false                 # true = record every candidate's PTR verdict to a CSV
seen_log_file: seen.csv         # relative to script dir; grows over time (rotate it)
```

### Dry-run first (confirms login + shows the computed port set, writes nothing)

```
DOMAINBLOCK_DRYRUN=1 DOMAINBLOCK_DEBUG=1 ruby /opt/domainblock/domainblock.rb
```

Expect: `Loaded N pattern(s)` → `Queue domainblock-check: …` → `Run complete` →
`watched-ports: … -> 80,3210,7277,8123` (your tagged set). In dry-run the
watched-ports line is computed and logged but **not written**. A `Cannot connect`
error means the router IP/credentials or API service/allowed-address is wrong.

### Install the background service

```
sudo ./install.sh          # runs every 30s
sudo ./install.sh 60       # or every 60s
```

The installer creates the `domainblock` service user, writes the systemd
service + timer pointed at this directory, sets `config.yml` to 640
root:domainblock (it holds the password), and starts the timer.

### Verify the SERVICE run (not just your manual run)

```
systemctl list-timers domainblock.timer
sudo systemctl start domainblock.service
journalctl -u domainblock.service -n 15 --no-pager
```

You want clean `Loaded / Queue / Run complete / watched-ports` lines running as
the service user. A `CHDIR / Permission denied` here means the folder is still in
a home directory — see the /opt note above.

---

## 3. Testing the pipeline end-to-end

> **Gotcha:** don't test with `8.8.8.8` and pattern `*.dns.google`. `8.8.8.8`
> reverse-resolves to the **bare** `dns.google` (no leading label), and `*`
> requires at least one label — so it correctly does NOT match. That's the same
> anchoring that stops suffix-spoofing; it's working as designed. Use a **bare**
> pattern for that test IP:

```
# on the Linux box: add a matching pattern
echo "dns.google" >> /opt/domainblock/domainblock-patterns.txt

# on the router: queue the IP as if it had just connected
/ip firewall address-list add list=domainblock-check address=8.8.8.8 timeout=5m

# on the Linux box: run once
ruby /opt/domainblock/domainblock.rb        # expect: BANNED 8.8.8.8 (PTR dns.google)

# on the router: confirm it landed
/ip firewall address-list print where list=domainblock-banned
```

Then CLEAN UP the test:

```
# Linux box: delete the "dns.google" line from domainblock-patterns.txt
# router:
/ip firewall address-list remove [find where list=domainblock-banned address=8.8.8.8]
```

Your real patterns (`*.googleusercontent.com`, etc.) match multi-label attacker
PTRs like `189.167.182.34.bc.googleusercontent.com` correctly — that's the
normal case; only the bare-hostname test IP needs a bare pattern.

### Confirming the forward/DSTNAT path specifically

The forward path is the one that catches services hosted behind the router, and
it's the path that broke in the original bug — so test it explicitly.

**1. Confirm the queue rule is matching.** Reset its counter and watch it climb:

```
/ip firewall filter reset-counters [find chain=forward action=add-src-to-address-list comment~"#domainblock"]
# wait a few minutes, or hit a forwarded service from an external network, then:
/ip firewall filter print stats where chain=forward action=add-src-to-address-list comment~"#domainblock"
```

A **frozen** counter means the rule is matching nothing — check for the
`dst-address-list` trap (section 1e) or that `connection-nat-state=dstnat` is set.

**2. Confirm the derived port set is what you intend:**

```
DOMAINBLOCK_DRYRUN=1 DOMAINBLOCK_DEBUG=1 ruby /opt/domainblock/domainblock.rb
# -> watched-ports: ... -> 80,3210,7277,8123
```

**3. Watch a real ban happen** as scanner traffic arrives:

```
journalctl -u domainblock.service -f
```

---

## 4. Managing / operating

**Add / remove a block pattern:** edit `domainblock-patterns.txt`, one glob per
line. No restart needed — the next run picks it up.

Pattern syntax: `*` matches one or more DNS labels. `*.googleusercontent.com`
matches `foo.bc.googleusercontent.com`, and is anchored at the end so
`x.googleusercontent.com.evil.com` does NOT match.

**Add / remove a watched forwarded service:** tag (or untag) the NAT `dst-nat`
rule with `#domainblock`. No restart, no rule edit — the script reconciles the
forward queue rule's `dst-port` on the next run.

```
# what's currently blocked (comment shows which PTR matched)
/ip firewall address-list print where list=domainblock-banned

# what's currently being watched (the managed forward rule)
/ip firewall filter print where chain=forward action=add-src-to-address-list comment~"#domainblock"

# which NAT rules feed the watched set
/ip firewall nat print where comment~"#domainblock"

# all domainblock filter rules at a glance
/ip firewall filter print where comment~"#domainblock"

# manually unban an IP
/ip firewall address-list remove [find where list=domainblock-banned address=1.2.3.4]

# watch the service
journalctl -u domainblock.service -f
```

**Manually unbanning:** removing an IP from `domainblock-banned` on the router is
enough — on the next cache refresh (persist), it drops out of `ban-cache.txt`
too, so it won't be restored. If you unban an IP and it keeps coming back
*within* a refresh window, wait for the next refresh or clear it from the cache
file directly (`ban-cache.txt` in the script dir) and delete
`/tmp/domainblock-run-counter` to force a refresh.

**Force a ban-cache refresh now:** `rm /tmp/domainblock-run-counter`; the next
run restores + persists regardless of the counter.

### Finding new domains to ban (recon log)

Scanners come from far more than AWS and Google — Censys, Shodan, Onyphe,
BinaryEdge, Stretchoid, Linode, Contabo and others scan constantly. To discover
which providers are hitting you that your patterns *don't* yet catch, enable the
recon log (`seen_log: true` in config). The script then records every
candidate's verdict to `seen.csv` — using the PTR (and, if `asn_check` is on,
the ASN) it already looked up during the normal run, so no extra DNS work:

```
timestamp,ip,ptr,verdict,detail
# verdict = banned-ptr | banned-asn | no-match | no-ptr
# detail  = matched PTR pattern for banned-ptr; "AS<num> <name>" for
#           banned-asn, or for no-match/no-ptr rows where asn_check found an
#           ASN that just isn't in domainblock-asn-patterns.txt yet
```

The `no-match` rows are the gold: IPs that connected but **weren't** banned —
exactly the candidates to consider. Tally their domain suffixes:

```
awk -F, '$4=="no-match"{print $3}' /opt/mikrotik_blockdomain/seen.csv \
  | sed -E 's/^[^.]+\.//' | sort | uniq -c | sort -rn | head -30
```

A cloud/scanner provider trending near the top is a pattern worth adding to
`domainblock-patterns.txt`.

If `asn_check` is on, do the same against column 5 to find ASN names worth
adding to `domainblock-asn-patterns.txt` — this is what catches the `no-ptr`
rows too, since those are exactly the IPs reverse-DNS matching can't see:

```
awk -F, '$5!=""{print $5}' /opt/mikrotik_blockdomain/seen.csv \
  | sort | uniq -c | sort -rn | head -30
```

Common scanner suffixes worth blocking once you see them: `*.censys-scanner.com`,
`*.shodan.io`, `*.onyphe.net`, `*.binaryedge.ninja`, `*.stretchoid.com`,
`*.internet-measurement.com`, `*.modat.io`, `*.internet-census.org`,
`*.bufferover.run`, `*.linodeusercontent.com`, `*.contaboserver.net`. Do NOT
blanket-block residential/ISP suffixes (e.g. a national telco) — those may be
legitimate users or your own backup WAN.

`seen.csv` rotation is handled for you — `install.sh` drops in
`/etc/logrotate.d/domainblock` (monthly, 6 kept, compressed) the first time you
run it, so there's no manual truncation to remember. Without the recon log you
can still spot patterns by reverse-resolving the syslog feed, but that re-does
hundreds of DNS lookups each time — the recon log captures them once, for free.

Doing this by hand with `awk` (above) is fine for an on-demand check, but it
only ever looks at whichever single file you point it at, and won't notice a
source that never has enough volume in one month to catch your eye. See
**Monthly pattern-coverage report** below for the automated, multi-month
version of this same idea.

### Optional: block by datacenter/ASN too

PTR matching structurally can't catch a datacenter IP that just has **no PTR
record** — the reverse-lookup returns nothing to match against, so the IP is
logged as `no-ptr` and never banned, no matter what's in
`domainblock-patterns.txt`. Set `asn_check: true` in `config.yml` to add a
second, independent signal: for any candidate PTR matching didn't already ban,
the script looks up which network (Autonomous System) the IP belongs to and
checks its name against `domainblock-asn-patterns.txt`.

The lookup uses [Team Cymru's whois-over-DNS
service](https://asn.cymru.com/#whois) — two plain DNS TXT queries, the same
`Resolv` stdlib already used for the PTR lookup. No gem, no local GeoIP/ASN
database to download or keep current, and it only runs for candidates that
weren't already banned by PTR, so it adds no extra queries for the common case.

```
/opt/domainblock/domainblock-asn-patterns.txt   # one glob per line, e.g. *HETZNER*
```

Unlike the PTR patterns (label-anchored: `*.example.com` matches
`foo.example.com`), ASN names are free text — company names, commas, dashes
(e.g. `NextGenWebs-NL - NextGenWebs, S.L., ES`) — so these patterns are matched
as a plain case-insensitive glob against the whole name.

**Worked example** (from testing this feature): `185.213.175.37` has no PTR at
all — the existing script would silently pass it through. Its ASN resolves to
`AS41608, NextGenWebs-NL - NextGenWebs, S.L., ES`, a Spanish hosting provider,
which the ban comment records as:

```
domainblock: ASN AS41608 NextGenWebs-NL - NextGenWebs, S.L., ES @2026-09-05T...
```

You won't know most regional hosting-provider names in advance the way you
know AMAZON/HETZNER/OVH. Turn on `seen_log` (previous section) and let it run
for a while — every unmatched candidate that has an ASN gets that name logged
in the `detail` column, so you can see which providers are actually hitting
you before deciding which ones to add.

Not a substitute for `domainblock-patterns.txt` — most datacenter IPs already
carry a matching PTR, so this mainly closes the no-PTR gap and gives
defense-in-depth for the providers you specifically list. It's also not
country-level GeoIP blocking; it identifies the network operator, not the
country, which is what "block this datacenter" actually calls for.

### Optional: monthly pattern-coverage report (mechanical, emailed)

Set `monthly_report: true` in `config.yml` and `domainblock-monthly-report.rb`
runs automatically on its own systemd timer (installed by `install.sh`, fires
the 3rd of each month — a couple days after logrotate's own daily cron, so
there's always a completed archive to read). It re-does the `awk`-based recon
workflow above for you every month and emails only what's genuinely new:

- **This month, by volume** — top PTR suffixes and ASN names NOT already in
  `domainblock-patterns.txt` / `domainblock-asn-patterns.txt`, ranked by hit
  count, same as the manual `awk` workflow above.
- **Persistent, across everything logrotate is still keeping** (up to 6
  months) — sources seen on many separate **days**, ranked by day-count
  rather than volume. This is the one the volume list structurally can't
  provide: a source that only ever sends a handful of hits, but comes back
  every few days for months, never ranks near the top of any single month's
  totals — an attacker deliberately pacing attempts to stay under exactly that
  radar. `report_persistent_min_days` (default 3) sets how many distinct days
  before something gets flagged this way.

Both sections stay mechanical, same spirit as the recon log itself: it tells
you what's new and how big it is, not whether it's safe to block. A benign
self-identifying scanner and a bulletproof host can look identical in these
numbers — deciding between them still takes an actual look, the same way it
did when you found `security.ipip.net` or `visionheight.com` by hand.

**Config needed** (`config.yml`):

```yaml
monthly_report: false                # true = enable
report_top_n: 20                     # how many items per section
report_persistent_min_days: 3        # distinct-day threshold for the persistence sections
report_smtp_host: smtp.example.com
report_smtp_port: 587
report_smtp_user: reports@example.com
report_smtp_pass: CHANGE_ME
report_smtp_starttls: true
report_from: "domainblock@yourhost"   # for Gmail: must match report_smtp_user, see below
report_to: "you@example.com"          # comma-separate for multiple recipients
```

Requires `seen_log: true` (previous section) and at least one rotated archive
to exist — it never reads the live, still-growing `seen.csv`.

**Test it without waiting for a real rotation or sending real mail:**

```
DOMAINBLOCK_REPORT_ARCHIVE=/opt/domainblock/seen.csv DOMAINBLOCK_DRYRUN=1 DOMAINBLOCK_DEBUG=1 \
  ruby /opt/domainblock/domainblock-monthly-report.rb
```

`DOMAINBLOCK_REPORT_ARCHIVE` points the script at any file directly — the live
`seen.csv` included — instead of searching for a rotated `seen.csv-YYYY-MM`.
`DOMAINBLOCK_DRYRUN=1` prints the report instead of emailing it. Drop the
dry-run flag once your SMTP settings are real to confirm actual delivery.

> **Lesson learned: Gmail rejects a From address it doesn't recognize.**
> `Net::SMTPFatalError: 555 5.5.2 Syntax error` from Gmail's relay almost
> always means `report_from` doesn't match (or belong to) the account
> authenticated as `report_smtp_user` — Gmail phrases this as a generic syntax
> error, but it's really an address-identity check. Set `report_from` to the
> exact same address as `report_smtp_user` (a real Gmail address, or a verified
> alias on that account), not an arbitrary placeholder domain.

---

## 5. Uninstall

```
sudo ./uninstall.sh              # remove service + timer + service user
sudo ./uninstall.sh --keep-user  # keep the service account
```

Leaves the folder and your config/patterns intact and does not touch the router.
To clean the router side too, remove the seven `#domainblock` filter rules and
the two address-lists, and strip the `#domainblock` tag from your NAT rules
(leave the NAT rules themselves — they're your real port-forwards):

```
/ip firewall filter remove [find comment~"#domainblock"]
/ip firewall address-list remove [find list=domainblock-check]
/ip firewall address-list remove [find list=domainblock-banned]
```

The ban cache and run counter are local files; remove them if you want a clean
slate: `rm -f ban-cache.txt /tmp/domainblock-run-counter`.

---

## Notes / limitations

- **Input vs forward:** the input queue rule only records traffic terminating on
  the router; the forward queue rule records DSTNAT'd traffic to services on
  other hosts. Most home setups use forward exclusively and disable the input
  rule. Omitting the forward rule is the original cause of a matching domain
  still reaching a service that lives behind the router.
- **The script manages only the forward queue rule's `dst-port`** — derived from
  NAT rules tagged `#domainblock` (`to-ports`, fallback `dst-port`). It never
  touches NAT rules, the input rule, ordering, or any other match condition. Do
  not add extra match conditions to the forward queue rule (see the trap in 1e).
- **UPnP/NAT-PMP is excluded for free:** dynamic NAT mappings are skipped, so a
  torrent/game client punching its own forward doesn't get PTR-watched or flood
  the candidate list.
- Catches hosts that HAVE a matching PTR — cloud scanners almost always do
  (googleusercontent / amazonaws / etc.), which is exactly the target case.
  Attackers on residential IPs with no PTR won't be caught by reverse-DNS
  matching; IP-reputation tools (e.g. CrowdSec) are the complement for those.
  A datacenter IP with no PTR is a narrower case the optional `asn_check`
  (see "Optional: block by datacenter/ASN too") can catch instead, since ASN
  membership doesn't depend on the provider having set rDNS at all.
- **Reactive by up to one interval:** a brand-new IP gets a connection or two
  through before its next-run lookup bans it. Fine for brute-force attempts.
- **Bans are dynamic and RAM-only on the router** — wiped on reboot. The ban
  cache (section 1f) restores them on the next refresh run, so a scheduled
  reboot doesn't lose them, but there's an up-to-`ban_cache_every`-interval gap
  after a router reboot before the list is refilled (default ~30 min).
- **The script never sees the attack port.** It reads only source IPs from
  `domainblock-check`; the port lives solely in the firewall log line
  (`dblock-fwd …->host:port`). So bans, the cache, and PTR analysis are all
  IP-based. To see which port was hit, ship the queue-rule logs to a syslog host
  (see the remote-logging notes) — that's the only source of IP+port.
- The queue rules (`add-src-to-address-list`) do not block — they only record,
  so their position in the chain doesn't matter. Only the VPN-accepts and drops
  are order-sensitive.
- **Failover-safe:** if both WANs (e.g. fibre + LTE) are in the `WAN` interface
  list, the queue and drop rules apply on whichever path is active. The
  watched-ports match is on internal destination port (post-NAT), so it's
  WAN-path-agnostic. Verify both WANs are members: `/interface list member print where list=WAN`.
- RouterOS 7.x plaintext `/login` over the API channel: on 8728 the password
  crosses your LAN in the clear. Enable API-SSL (8729, `router_tls: true`) to
  encrypt it.
- **The monthly report's persistence check is bounded by retention.** It reads
  every archive logrotate is still keeping (6 months by default), so an
  attacker pacing attempts further apart than that window is invisible to it,
  same as it's invisible to everything else here. Raising `rotate` in the
  logrotate config extends the window at the cost of more disk.
