# domainblock — reverse-DNS pattern blocker for MikroTik

Blocks inbound IPs whose **reverse-DNS (PTR)** hostname matches a pattern you
control (e.g. `*.googleusercontent.com`). The router queues new inbound source
IPs; a small Ruby script on your Linux box looks up each one, matches it against
your pattern list, and writes matches to a MikroTik address-list that a drop
rule uses. Matched IPs are blocked from **everything except your VPN ports**, so
you can never lock yourself out of remote access.

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

Legitimate users are never on `domainblock-banned`, so they never match the
block rules at all — the rules are inert until the script bans something.

> **Where your services live matters — read this before you configure.**
> The recorder that feeds detection is an `add-src-to-address-list` rule. A rule
> in the **input** chain only sees traffic that terminates **on the router
> itself**. Services that run on another box (Home Assistant on a separate host,
> Plex on a NAS, etc.) are reached via **DSTNAT port-forwarding**, and that
> traffic traverses the **forward** chain, never input. So you need a queue rule
> in **both** chains — input for anything hosted on the router, forward for
> anything DSTNAT'd behind it. If you only add the input queue rule, scanners
> hitting your forwarded services are never recorded, never looked up, and never
> banned, even though the pattern would have matched. Section 1c adds both.

---

## Files (all in one folder)

```
domainblock.rb               the script (reads config + patterns from its own dir)
config.yml                   router IP, credentials, list names, timeouts
domainblock-patterns.txt     your block patterns — the thing you edit
install.sh                   sets up the systemd service + timer
uninstall.sh                 removes them
README.md                    this file
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

### 1b. Enable + restrict the API to your Linux box

```
/ip service set api address=<HA_LINUX_IP>/32 disabled=no
# confirm:
/ip service print where name=api
```

(Plain API on 8728 sends the password in the clear over your LAN. For TLS, use `api-ssl` on 8729 and set `router_port: 8729` + `router_tls: true` in config.yml.)

### 1c. Add the rules (IMPORTANT: do NOT use `place-before`)

> **Lesson learned during install:** `place-before=[find where comment~"..."]` repeatedly failed with *"invalid internal item number" / "no such item"* because the `~` regex chokes on special characters in RouterOS comments
> (commas, double spaces). **Add every rule plain, then position it with `move` by number.** Exact-match `find` (`comment="..."` with `=`) works for `move`; the regex `~` at add-time does not.

Add all seven rules (they append at the bottom — that's fine, we move the
order-sensitive ones next):

```
/ip firewall filter add chain=input action=add-src-to-address-list address-list=domainblock-check address-list-timeout=1m in-interface-list=WAN connection-state=new protocol=tcp dst-port=8123,7277,3120,32400,5006,8080,8081,31011 comment="domainblock: queue new inbound (input) for PTR check"
/ip firewall filter add chain=forward action=add-src-to-address-list address-list=domainblock-check address-list-timeout=1m in-interface-list=WAN connection-state=new connection-nat-state=dstnat protocol=tcp comment="domainblock: queue new inbound (forward/DSTNAT) for PTR check"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=udp dst-port=13231-13239,1194,1701,500,4500 comment="domainblock: allow WG/OpenVPN/L2TP even if banned"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=tcp dst-port=1723,8291 comment="domainblock: allow PPTP/Winbox even if banned"
/ip firewall filter add chain=input action=accept src-address-list=domainblock-banned protocol=gre comment="domainblock: allow PPTP GRE even if banned"
/ip firewall filter add chain=input action=drop src-address-list=domainblock-banned in-interface-list=WAN comment="domainblock: drop matched IPs (input)"
/ip firewall filter add chain=forward action=drop src-address-list=domainblock-banned in-interface-list=WAN comment="domainblock: drop matched IPs (forward)"
```

**About the two queue rules:**

- The **input** queue rule records scanners that hit a service **terminating on
  the router itself** — anything you expose with an `input action=accept` rule.
  Adjust its `dst-port` to exactly those ports. The example set is: HA 8123,
  Bitwarden 7277, Linkwarden 3120, Plex 32400, WebDAV 5006, Kodi 8080/8081,
  MySQL 31011 — but only the ones actually running *on* the router belong here.
- The **forward** queue rule records scanners that hit a service **DSTNAT'd to
  another host** (HA on a Proxmox box, Plex on a NAS, etc.). It deliberately has
  **no `dst-port`** and matches on `connection-nat-state=dstnat` instead, so it
  covers every forwarded service at once and won't silently miss a service if
  you remap a port later. If a service is reached by port-forward, this is the
  rule that catches its scanners — the input queue rule never will.

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

1. (your existing `Blocked-External` drop, if any)
2. domainblock VPN-accept — UDP (WG/OpenVPN/L2TP)
3. domainblock VPN-accept — TCP (PPTP/Winbox)
4. domainblock VPN-accept — GRE
5. domainblock input drop
6. …then your service accepts, `accept established,related`, etc.

> **Critical placement detail:** the input drop must sit **above your
> per-service accept rules** (Bitwarden, Plex, Linkwarden, …), not merely above `accept established,related`. If it sat below them, a banned IP hitting one of
> those service ports would be accepted before reaching the drop. Put it right
> after your existing top-of-chain drop (e.g. `Blocked-External`). The three
> VPN-accepts go immediately above the drop so the carve-out is evaluated first.

**Forward chain:** the domainblock forward drop goes **above** `defconf: drop all from WAN not DSTNATed`.

> **Note on the forward drop and `established,related`:** most configs have
> `defconf: accept established,related` high in the forward chain, above the
> domainblock forward drop. That's fine — a banned IP's **new** connections
> still hit the drop (new connections don't match established). The only residue
> is that a single connection opened during the up-to-one-interval reactive
> window rides `established,related` until it closes. For brute-force / scanner
> traffic that's harmless, so leave the forward drop where the target ordering
> puts it rather than moving it above the established-accept (moving it risks
> tearing down legitimate forwarded sessions every time something is banned).

Example moves (substitute your real numbers from the print):

```
# input drop -> just after your Blocked-External drop (e.g. to position 6)
/ip firewall filter move <input-drop#> destination=<blocked-external-drop#+1>
# the three VPN-accepts -> immediately above the input drop
/ip firewall filter move <vpn-udp#> destination=<input-drop#>
/ip firewall filter move <vpn-tcp#> destination=<input-drop#>
/ip firewall filter move <vpn-gre#> destination=<input-drop#>
# forward drop -> just before "drop all from WAN not DSTNATed"
/ip firewall filter move <forward-drop#> destination=<wan-not-dstnat#>
```

Do moves one at a time and re-print if numbers shift. Verify the final order
before trusting it:

```
/ip firewall filter print where chain=input
/ip firewall filter print where chain=forward
```

---

## 2. Linux box setup

No dependencies — stock Ruby 3.x has everything (socket, resolv, yaml, openssl).

### Install location — use /opt, not your home directory

> **Lesson learned:** running the service from `/home/<user>/...` fails with `status=200/CHDIR — Changing to the requested working directory failed: Permission denied`, because home directories are mode 700 and the unprivileged `domainblock` service user can't traverse into them. Put the folder under `/opt`.

```
sudo mv ./mikrotik_blockdomain /opt/domainblock    # or copy the folder there
cd /opt/domainblock
```

(If you must keep it under a home dir, `sudo chmod 755 /home/<user>` makes the
directory traversable — but /opt is cleaner.)

### Configure

Edit `config.yml` — set `router_host`, `router_pass` (and for API-SSL: `router_port: 8729` + `router_tls: true`).

### Dry-run first (confirms the router login works)

```
ruby /opt/domainblock/domainblock.rb
# or with detail:
DOMAINBLOCK_DEBUG=1 ruby /opt/domainblock/domainblock.rb
```

Expect: `Loaded N pattern(s)` → `Queue domainblock-check: … ` → `Run complete`.
A `Cannot connect` error means the router IP/credentials or API service/allowed
-address is wrong.

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

You want clean `Loaded / Queue / Run complete` lines running as the service
user. A `CHDIR / Permission denied` here means the folder is still in a home
directory — see the /opt note above.

---

## 3. Testing the pipeline end-to-end

> **Gotcha:** don't test with `8.8.8.8` and pattern `*.dns.google`. `8.8.8.8` reverse-resolves to the **bare** `dns.google` (no leading label), and `*` requires at least one label — so it correctly does NOT match. That's the same
> anchoring that stops suffix-spoofing; it's working as designed. Use a **bare** pattern for that test IP:

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

If you run services behind the router (HA, Plex, etc.), test the forward path,
not just input — the two are recorded by different rules:

```
# watch the service live
journalctl -u domainblock.service -f
```

Trigger a hit against a **DSTNAT'd** service (or wait for a real scanner), then
confirm the source IP first appears in `domainblock-check` and, within a run or
two, lands in `domainblock-banned`:

```
/ip firewall address-list print where list=domainblock-check
/ip firewall address-list print where list=domainblock-banned
```

If a scanner reaches a forwarded service but never shows up in either list, the
forward queue rule (section 1c) is missing or disabled — that's the single most
common reason a "banned" domain still gets through to a service that lives on
another host.

---

## 4. Managing / operating

**Add / remove a block pattern:** edit `domainblock-patterns.txt`, one glob per
line. No restart needed — the next run picks it up.

Pattern syntax: `*` matches one or more DNS labels. `*.googleusercontent.com` matches `foo.bc.googleusercontent.com`, and is anchored
at the end so `x.googleusercontent.com.evil.com` does NOT match.

```
# what's currently blocked (comment shows which PTR matched)
/ip firewall address-list print where list=domainblock-banned

# manually unban an IP
/ip firewall address-list remove [find where list=domainblock-banned address=1.2.3.4]

# watch the service
journalctl -u domainblock.service -f
```

---

## 5. Uninstall

```
sudo ./uninstall.sh              # remove service + timer + service user
sudo ./uninstall.sh --keep-user  # keep the service account
```

Leaves the folder and your config/patterns intact and does not touch the router.
To clean the router side too, run the commands the uninstaller prints (removing
the firewall rules and the two address-lists). If you moved/renamed the folder,
run uninstall from wherever it now lives before deleting it.

---

## Notes / limitations

- **Input vs forward:** the input queue rule only records traffic terminating on
  the router; the forward queue rule records DSTNAT'd traffic to services on
  other hosts. You need both. Omitting the forward rule is the usual cause of a
  matching domain still reaching a service that lives behind the router (see
  section 1c).
- Catches hosts that HAVE a matching PTR — cloud scanners almost always do
(googleusercontent / amazonaws / etc.), which is exactly the target case.
Attackers on residential IPs with no PTR won't be caught by reverse-DNS
matching; IP-reputation tools (e.g. CrowdSec) are the complement for those.
- Reactive by up to one interval: a brand-new IP gets a connection or two
through before its next-run lookup bans it. Fine for brute-force attempts.
- The queue rules (`add-src-to-address-list`) do not block — they only record,
so their position in the chain doesn't matter. Only the VPN-accepts and drops
are order-sensitive.
- RouterOS 7.x plaintext `/login` over the API channel: on 8728 the password
crosses your LAN in the clear. Enable API-SSL (8729, `router_tls: true`) to
encrypt it.
