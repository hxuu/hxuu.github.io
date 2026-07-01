---
title: "Building an AWS-Style VPC with Private Subnets and NAT Using OVN"
description: "I built a 5-node OVN cluster on libvirt, implemented a VPC with private subnets, SNAT, and load balancing, debugging through a database crash, stale chassis references, a per-chassis conntrack design constraint, and deep OpenFlow tracing. Full technical walkthrough."
date: 2026-06-30T00:00:00+01:00
tags: ["networking", "ovn", "ovs", "devops", "infrastructure", "linux", "virtualization", "load-balancing"]
authors: ["hxuu"]
draft: true
---

There's a specific kind of satisfaction that comes from building infrastructure
that actually looks like what a hyperscaler runs — except you're doing it on
your own machine with libvirt and some shell scripts.

I wanted to understand how cloud VPCs work under the hood. Not the marketing
version ("we use SDN!"), but the actual mechanics: logical switches, distributed
routers, gateway chassis, SNAT. How packets flow from a private subnet to the
internet. What happens when a database cluster crashes mid-session. Why a single
wrong `options:chassis` string can silently break all north-south traffic.

This is that journey.

## 1. What We're Building

The goal is a VPC topology that mirrors AWS's private subnet + NAT Gateway
pattern:

```
           Internet (192.168.200.0/24)
                    │
              ┌─────┴─────┐
              │  Gateway   │  ← pinned to ovn-gw chassis
              │   Router   │     SNAT: 10.0.2.0/24 → 192.168.200.254
              └─────┬─────┘
                    │
              ┌─────┴─────┐
              │  Public    │
              │  Subnet    │  10.0.1.0/24
              └─────┬─────┘
                    │
              ┌─────┴─────┐
              │  VPC       │  ← distributed router
              │  Router    │     10.0.1.1 (public-facing)
              └─────┬─────┘     10.0.2.1 (private-facing)
                    │
              ┌─────┴─────┐
              │  Private   │
              │  Subnet    │  10.0.2.0/24
              │
            ┌─┴─┐
            │ VM │ 10.0.2.10
            └───┘
```

A workload in the private subnet (10.0.2.10) can reach the internet (simulated
by 192.168.200.10) via SNAT. The source address is rewritten to 192.168.200.254
— the gateway router's provider-facing IP. Inbound traffic from the internet
routes through but doesn't get DNAT (no public IP assigned to the private VM).

For the underlay, I use a 5-node cluster of Debian 13 VMs on libvirt/qemu:

| Node | Role | IP |
|------|------|----|
| ovn-c1, ovn-c2, ovn-c3 | OVN control (NB/SB DB + northd) | 192.168.100.{11,12,13} |
| ovn-gw | Gateway (external connectivity) | 192.168.100.20 |
| ovn-compute | Compute (workload host) | 192.168.100.30 |

All VMs run in a NAT'd libvirt network (`ovn-underlay`, 192.168.100.0/24) with
GENEVE tunnels between the hypervisors for the overlay.

## 2. The Underlay: libvirt + Debian Preseed

I'll keep the underlay setup brief since it's fairly standard, but a few things
are worth calling out.

**Preseed gotcha**: Debian's installer has a UI step for creating a user account
that can get stuck even when you've configured `passwd/root-password`. The fix
is `d-i passwd/make-user boolean false` — root-only install, no unprivileged
user. This sidesteps the bug entirely.

**Kernel cmdline**: I pass `net.ifnames=0 console=ttyS0,115200` to force
legacy interface naming (`eth0` instead of `enp1s0`) and enable serial console.
Without this, ansible-style host naming breaks predictably.

**Post-install via guest agent**: Instead of DHCP, I assign static IPs through
the guest agent after the first boot. This lets me control the addressing
scheme without touching the preseed. The `late.sh` script injected via
`--initrd-inject` handles SSH key injection, virtio module inclusion in
initramfs, and GRUB serial console configuration.

```bash
virt-install \
  --name ovn-central-01 \
  --memory 2048 \
  --vcpus 2 \
  --disk /home/hxuu/libvirt/images/ovn-central-01.qcow2,size=8 \
  --network network=ovn-underlay \
  --location /home/hxuu/libvirt/iso/debian-13.5.0-amd64-netinst.iso \
  --initrd-inject preseed.cfg \
  --initrd-inject late.sh \
  --extra-args "auto console=ttyS0,115200 net.ifnames=0" \
  --wait 0
```

One trap: `virsh net-destroy` followed by `virsh net-start` breaks the
bridge-to-tap connectivity. The VMs must be `virsh destroy` + `virsh start` to
reconnect. Not a bug per se — more of a "don't restart the NAT network while
VMs are using it" lesson.

## 3. OVN Architecture: NB, SB, and RAFT

OVN separates its control plane into two databases, and understanding this
distinction is critical to debugging anything that follows.

From `ovn-architecture(7)`:

> The OVN system stores its logical network configuration in the OVN Northbound
> Database (NB). ovn-northd translates this high-level intent into logical
> datapath flow entries in the OVN Southbound Database (SB). Each
> ovn-controller instance connects to the SB and translates those flows into
> OpenFlow for its local ovs-vswitchd.

The flow is:

```
ovn-nbctl → NB DB (6641) → ovn-northd → SB DB (6642) → ovn-controller → ovs-vswitchd → datapath
```

Three databases to worry about: NB, SB, and OVS (local to each hypervisor).
Each of NB and SB runs on all three control nodes as a RAFT cluster — meaning
one leader, two followers, and every write must go through the leader.

The leader election and replication happen inside `ovsdb-server` itself.
OVSDB supports RAFT natively since OVS 2.11. You configure the cluster by
passing all three peers to `--remote=ptcp:...` and `--db-cluster-local-addr`.

```bash
ovsdb-server \
  /etc/ovn/ovnnb_db.db \
  --remote=ptcp:6641:192.168.100.11 \
  --remote=punix:/var/run/ovn/ovnnb_db.sock \
  --db-cluster-local-addr=192.168.100.11 \
  --db-cluster-remote-addr=192.168.100.12 \
  --db-cluster-remote-addr=192.168.100.13
```

One critical detail: you must bind to the specific IP, not 0.0.0.0. If you use
`ptcp:6641:0.0.0.0`, the RAFT cluster will form but the leader address
advertised in the cluster will be wrong (it'll resolve the hostname to an
unexpected IP). More on this later.

### Why Three Control Nodes?

The RAFT consensus protocol requires a majority (quorum) to commit a write.
With 3 nodes, you can lose 1 and still have quorum. With 2, you can't lose
any — that's an availability regression compared to a single node. With 3,
you get fault tolerance while keeping the cluster small.

From `ovsdb-server(1)`:

> The cluster is based on the Raft consensus algorithm. For a cluster to
> make progress, more than half of the servers must be available.

## 4. The VPC Topology

With the cluster running, I defined the logical topology. This is where OVN's
abstractions start to shine. Three logical switches, two logical routers, SNAT.

```bash
# Logical switches
ovn-nbctl ls-add ls-example1-provider   # "internet" subnet
ovn-nbctl ls-add ls-example1-pub        # transit subnet between routers
ovn-nbctl ls-add ls-example1-priv       # private workload subnet

# Gateway router (pinned to ovn-gw chassis)
ovn-nbctl lr-add gw-r-example1
ovn-nbctl set Logical_Router gw-r-example1 options:chassis=$GW_CHASSIS

# VPC router (distributed — lives on every hypervisor)
ovn-nbctl lr-add lr-example1
```

The distinction between the two routers is important.

**gw-r-example1** is a *gateway router* — it's pinned to a specific chassis
(ovn-gw) using `options:chassis`. All traffic through this router is
processed by ovs-vswitchd on that one machine. This is where SNAT lives,
because SNAT requires a fixed egress IP.

**lr-example1** is a *distributed router* — every chassis that has a port on
any of the connected logical switches runs a local instance. Traffic between
two VMs on the same chassis doesn't leave the host. This gives us data-plane
performance that scales horizontally.

The router ports connect the switches:

```
gw-r-example1-provider  192.168.200.254/24  →  ls-example1-provider
gw-r-example1-pub       10.0.1.254/24       →  ls-example1-pub
lr-example1-pub         10.0.1.1/24         →  ls-example1-pub
lr-example1-priv        10.0.2.1/24         →  ls-example1-priv
```

Routes and SNAT complete the picture:

```bash
# VPC router default route → gateway router
ovn-nbctl lr-route-add lr-example1 0.0.0.0/0 10.0.1.254

# Gateway router route back → VPC router
ovn-nbctl lr-route-add gw-r-example1 10.0.2.0/24 10.0.1.1

# SNAT: private subnet → gateway's provider IP
ovn-nbctl lr-nat-add gw-r-example1 snat 192.168.200.254 10.0.2.0/24
```

At this point I also created the test workloads. Each workload is a network
namespace with an OVS internal port bound to the corresponding logical port:

```bash
# On ovn-gw:
ovs-vsctl add-port br-int lsp-prov-srv type=internal \
  external_ids:iface-id=lsp-prov-srv
ip netns exec ns-provider ip addr add 192.168.200.10/24 dev lsp-prov-srv

# On ovn-compute:
ovs-vsctl add-port br-int lsp-priv-srv type=internal \
  external_ids:iface-id=lsp-priv-srv
ip netns exec ns-priv ip addr add 10.0.2.10/24 dev lsp-priv-srv
```

The `external_ids:iface-id` is how `ovn-controller` maps an OVS interface to
a logical port in the SB database. Without it, the controller doesn't know
which logical port this interface belongs to.

## 5. The Database Crash

This is where things got interesting.

I was verifying the cluster health when suddenly all six `ovsdb-server`
processes — NB and SB on all three control nodes — went silent. No crash
messages, no OOM, no segfault. Just... stopped.

The first challenge was getting them back up. The naive approach:

```bash
ovn-ctl start_nb_ovsdb
```

This failed because `ovn-ctl` resolves the hostname, which in my setup maps
to `192.168.100.1` — the libvirt host's gateway IP, not the VM's IP. The
RAFT cluster would form with the wrong address and immediately fail.

The fix was to bypass `ovn-ctl` entirely and start `ovsdb-server` directly,
binding to the correct IP:

```bash
ovsdb-server \
  /etc/ovn/ovnnb_db.db \
  --remote=ptcp:6641:192.168.100.11 \
  --db-cluster-local-addr=192.168.100.11 \
  --db-cluster-remote-addr=192.168.100.12 \
  --db-cluster-remote-addr=192.168.100.13 \
  --pidfile=/var/run/ovn/ovnnb_db.pid \
  --unixctl=/var/run/ovn/ovnnb_db.ctl \
  --detach --no-chdir
```

The `ovn-architecture(7)` man page explains:

> Each OVSDB server manages a single database. OVN uses three separate
> databases: OVN_Northbound, OVN_Southbound, and Open_vSwitch.

So three databases, potentially three different `ovsdb-server` processes per
node. The NB and SB databases run on the control nodes; the Open_vSwitch
database runs on every node.

After restart, the SB cluster elected a new leader — `192.168.100.12` instead
of the original `192.168.100.11`. This is expected RAFT behavior: the first
node to complete its database recovery and solicit votes becomes leader. It
also meant that any client hardcoded to talk to `.11` for SB operations would
get "not cluster leader" errors. All my `ovn-nbctl --db=tcp:...` commands
needed to target the new leader.

## 6. The Gateway Router Port Binding Bug

After restarting the databases and `ovn-northd`, the chassis re-registered with
the SB database. But they registered with *new* UUIDs. The old chassis entries
were gone.

This is a problem when you've hardcoded UUIDs.

My original setup script used:

```bash
GW_CHASSIS="0479739a-90ac-4937-ac1a-b94e9e7131ca"  # old UUID, now dead
COMPUTE_CHASSIS="6b7a72b6-b53d-4af3-8d79-74199ef9b3bd"  # old UUID, now dead
```

The gateway router was pinned to a UUID that no longer existed:

```bash
ovn-nbctl set Logical_Router gw-r-example1 \
  options:chassis="0479739a-90ac-4937-ac1a-b94e9e7131ca"
```

And the gateway chassis on the router port referenced the same stale UUID:

```bash
ovn-nbctl lrp-set-gateway-chassis gw-r-example1-pub \
  0479739a-90ac-4937-ac1a-b94e9e7131ca 100
```

After the restart, the Port_Binding table in the SB showed every
l3gateway-type port as unbound:

```
chassis                              logical_port
------------------------------------ ----------------------
[]                                   gw-r-example1-provider
[]                                   gw-r-example1-pub
[]                                   lsp-provider-gw
[]                                   lsp-pub-gw
```

All the router ports were orphaned. The l3gateway `options` still referenced
the old UUID, but no chassis matched it.

Meanwhile, `ovn-northd` was emitting this warning every 60 seconds:

```
WARN|Bad configuration: distributed gateway port configured on
     port gw-r-example1-pub on L3 gateway router
```

This warning is misleading if you don't know the full picture. What it's
actually telling you: the port `gw-r-example1-pub` has a `gateway-chassis`
configured, but the router `gw-r-example1` is already a gateway router
(pinned via `options:chassis`). Setting `gateway-chassis` on a port of a
gateway router is invalid — it's only meaningful on distributed routers,
where `gateway-chassis` designates which chassis should handle
gateway-destined traffic.

From `ovn-architecture(7)`:

> A gateway router is a logical router that acts as a gateway between the
> OVN logical networks and physical networks. It is always centralized on
> a single chassis.

And for distributed routers:

> A distributed router can have gateway chassis associated with some of its
> ports. This allows traffic destined to the gateway to be redirected to a
> specific chassis.

You can have a *distributed router with a gateway port* (the common pattern),
or a *gateway router* (fully centralized). You cannot mix the two — a gateway
router's ports don't take `gateway-chassis` because the router itself is
already centralized.

I had accidentally created that exact invalid mix: a gateway router whose
port also had `gateway-chassis` set.

## 7. The Fix: Stale Chassis and Design Correction

Two things needed fixing.

**First: remove the stale chassis reference from the gateway router.**

The `options:chassis` on `gw-r-example1` pointed to a UUID that no longer
existed. I updated it to use the *chassis name* instead of the UUID:

```bash
ovn-nbctl set Logical_Router gw-r-example1 options:chassis=ovn-gw
```

This is an important lesson about OVN identifiers. A chassis has both a UUID
(auto-generated) and a name (set via `ovs-vsctl set Open_vSwitch .
external_ids:hostname=ovn-gw`). The name persists across restarts. The UUID
does not. Whenever possible, use the name.

**Second: remove the redundant gateway-chassis from the port.**

```bash
ovn-nbctl lrp-del-gateway-chassis gw-r-example1-pub ovn-gw
```

After this, I forced `ovn-northd` to recompute:

```bash
ovn-appctl -t /var/run/ovn/ovn-northd.*.ctl inc-engine/recompute
```

Within seconds, the Port_Binding table showed the l3gateway ports bound to
the correct chassis:

```
chassis                              logical_port
------------------------------------ ----------------------
0f64b628-5611-443c-8e5f-64c1589b3dce gw-r-example1-provider
0f64b628-5611-443c-8e5f-64c1589b3dce gw-r-example1-pub
0f64b628-5611-443c-8e5f-64c1589b3dce lsp-provider-gw
0f64b628-5611-443c-8e5f-64c1589b3dce lsp-pub-gw
101f1431-4121-4d0b-bf03-c0ef896ec55f lsp-priv-srv
0f64b628-5611-443c-8e5f-64c1589b3dce lsp-prov-srv
```

The warning stopped. The router ports were alive.

## 8. Verification

All traffic paths now work:

**North-south SNAT** (private → internet):

```bash
# From ovn-compute's private namespace:
# ping 192.168.200.10 (the "internet" server on ovn-gw)
PING 192.168.200.10 (192.168.200.10) 56(84) bytes of data.
64 bytes from 192.168.200.10: icmp_seq=1 ttl=62 time=173 ms
64 bytes from 192.168.200.10: icmp_seq=2 ttl=62 time=0.614 ms
```

The first packet took 173ms (ARP resolution + flow setup), subsequent
packets under 1ms. TTL=62 confirms two router hops (lr-example1 → 63,
gw-r-example1 → 62).

The ARP table on the provider side confirms SNAT is active:

```bash
# On ovn-gw, inside ns-provider:
192.168.200.254 dev lsp-prov-srv lladdr 00:00:02:01:00:fe REACHABLE
```

The source is `192.168.200.254` — the SNAT address — not `10.0.2.10`.

**East-west** (private ↔ public subnets):

```bash
# From ovn-compute private namespace to VPC router:
PING 10.0.2.1 (10.0.2.1) 56(84) bytes of data.
64 bytes from 10.0.2.1: icmp_seq=1 ttl=64 time=0.386 ms
```

**Inbound routing** (internet → private via VPC router):

```bash
# From ovn-gw provider namespace to private VM:
PING 10.0.2.10 (10.0.2.10) 56(84) bytes of data.
64 bytes from 10.0.2.10: icmp_seq=1 ttl=62 time=1.13 ms
```

This works because the VPC router has a route `10.0.2.0/24 → lr-example1-priv`
and the gateway router has a route `10.0.2.0/24 → 10.0.1.1`. Inbound traffic
from the internet reaches the private subnet without DNAT. The return traffic
hits the SNAT rule and gets rewritten — creating symmetric routing through the
gateway router.

## 9. Load Balancing

With SNAT and east-west routing working, I wanted the next piece of the AWS VPC
puzzle: a load balancer. A VIP (virtual IP) that distributes TCP connections
across multiple backends, accessible both from within the private subnet
(hairpin traffic) and from external subnets through the router.

### 9.1 Creating the Load Balancer

OVN has native load balancing built into the logical switch and router
pipelines. You define a `Load_Balancer` object with VIP-to-backend mappings,
then attach it to a logical switch, a logical router, or both:

```bash
ovn-nbctl lb-add lb-example1 \
  10.0.2.100:80 \
  "10.0.2.10:80,10.0.2.11:80" \
  tcp

ovn-nbctl ls-lb-add ls-example1-priv lb-example1
ovn-nbctl lr-lb-add lr-example1 lb-example1
```

This creates a VIP `10.0.2.100:80` backed by two real servers on
`10.0.2.10:80` and `10.0.2.11:80`. The switch attachment makes the VIP
reachable from within the private subnet (hairpin). The router attachment
should, in theory, make it reachable from other subnets through the
distributed router.

The backends are simple `nc -l -p 80 -e /bin/bash` processes running
inside the private network namespaces, returning their hostname and
timestamp. Nothing fancy — just enough to prove that load
distribution works.

### 9.2 The Initial Test: Single-Subnet Works, Cross-Subnet Fails

Testing from within the private subnet succeeded immediately:

```bash
# From ns-priv (10.0.2.10) to VIP (10.0.2.100):
$ echo test | nc -w2 10.0.2.100 80
HTTP/1.1 200 OK
backend-11: arch - Tue Jun 30 08:09:00 PM CET 2026
```

The LB selected backend-11 (10.0.2.11), even though the client was
backend-10 (10.0.2.10). Hairpin routing worked — the SYN went to the VIP,
was DNAT'd to the other backend, and the SYN-ACK made it back.

But testing from the provider subnet (across the router) failed:

```bash
# From ns-provider (192.168.200.10) to VIP (10.0.2.100):
$ echo test | nc -w3 10.0.2.100 80
# ... hangs until timeout, no response
```

The TCP connection never completed. `tcpdump` on the provider side showed
SYN sent, SYN-ACK never received. The packets entered the network but
never came back.

This was the puzzle that consumed the rest of the session.

### 9.3 The Diagnosis: Per-Chassis Conntrack

To understand why cross-subnet LB failed, I traced the packet flow at the
OpenFlow level on both chassis, using `ovs-ofctl dump-flows br-int` with
per-table packet counters.

#### The Forward Path (SYN)

On the **gateway chassis** (ovn-gw), the packet from ns-provider to the VIP
enters the distributed router pipeline (`lr-example1`, metadata=0x5):

```
Table 15 (lr_in_defrag):
  ip, nw_dst=10.0.2.100 → ct(table=16, zone=reg11, nat)
  53 packets matched ✓

Table 17 (lr_in_dnat):
  ct_state=+new+trk, tcp, nw_dst=10.0.2.100, tp_dst=80 → group:2
  51 packets matched ✓
```

Group 2 committed the DNAT with backend selection:

```
group_id=2, type=select, selection_method=dp_hash
  bucket 0: ct(commit, nat(dst=10.0.2.10:80), exec(load:1→ct_mark[1]))
  bucket 1: ct(commit, nat(dst=10.0.2.11:80), exec(load:1→ct_mark[1]))
```

The critical action is `ct(commit, nat(dst=...))`. This creates a *conntrack
entry on the gateway chassis* mapping the original
`(192.168.200.10:XXXX → 10.0.2.100:80)` to
`(192.168.200.10:XXXX → 10.0.2.10:80)`.

After DNAT, the packet (now with dst=10.0.2.10) goes through ARP
resolution in table 29, which sets `dl_dst` to the backend's MAC. The
router then determines that the output port (`lsp-priv-srv`) is on a
remote chassis (ovn-compute) and performs a **chassis redirect**:

```
Table 65 (lr_out_chassis_direct):
  reg15=0x1, metadata=0x5 → clone(
    ct_clear,
    load:0x3→METADATA,  # switch private datapath
    load:0x2→REG14,     # chassis redirect key
    clear(reg0..reg10), resubmit(,8)
  )
  119 packets matched ✓
```

The clone enters the private switch pipeline on the gateway chassis. The
switch (table 42) encapsulates the packet in GENEVE and sends it to
ovn-compute:

```
Table 42 (switch chassis direct):
  reg15=0x1, metadata=0x3 → load:0x3→TUN_ID, tun_metadata0=0x1, output:4
  69 packets matched ✓
```

On the **compute chassis**, the GENEVE tunnel receives the packet (which
had `ct_clear` applied — conntrack state is gone). The switch delivers it
to the backend port:

```
Table 8: reg14=0x2, metadata=0x3 → load:1→XXREG0[114], resubmit(,9)
  30 packets arrived ✓

Table 42: reg15=0x1 → output:2 (local port lsp-priv-srv)
  98 packets matched ✓
```

The backend receives the SYN and sends a SYN-ACK. Forward path works.

#### The Return Path (SYN-ACK)

The SYN-ACK has `src=10.0.2.10:80, dst=192.168.200.10:XXXXX`. It enters
the private switch on the compute, gets delivered to the distributed
router (`lr-example1`), and the router processes it — but on the
**compute chassis**, not the gateway. Here's the problem.

On the compute, `lr-in-dnat` (table 17) has no conntrack entry for this
connection:

```
Table 17 (lr_in_dnat):
  # No ct_state=+est+trk match — the only flow is a priority-0 default
  82 packets matched, all through default ❌
```

The DNAT entry was committed on the **gateway** chassis's OVS conntrack
zone. Conntrack is per-chassis — the compute doesn't know about it. Without
a matching conntrack entry, OVS cannot reverse-NAT the source IP. The
SYN-ACK continues through the router pipeline with `src=10.0.2.10` (the
raw backend IP) instead of `src=10.0.2.100` (the VIP).

The router routes the packet to the provider network. On the gateway, the
provider VM receives a SYN-ACK from `10.0.2.10:80`. But its TCP socket is
expecting a SYN-ACK from `10.0.2.100:80` (the address it sent the SYN to).
The kernel drops it. No TCP handshake completes.

From `ovn-architecture(7)`:

> A distributed NAT implementation requires that the ingress and egress
> traffic for a connection traverse the same chassis to ensure that the
> conntrack entry is available for both directions.

The LB was attached to a *distributed* router. The ingress (SYN) hit the
gateway chassis; the egress (SYN-ACK) hit the compute chassis. Conntrack
lived on the gateway. The compute had nothing.

### 9.4 Deep Packet Tracing with OpenFlow

Before finding the root cause, I did systematic OpenFlow tracing on the
gateway chassis. The approach is straightforward but powerful:

1. **Identify the datapath metadata values.**
   For each logical switch/router, OVS assigns a unique `metadata` value.
   On the gateway chassis:
   - `metadata=0x2`: provider switch (`ls-example1-prov`)
   - `metadata=0x3`: private switch (`ls-example1-priv`)
   - `metadata=0x5`: distributed router (`lr-example1`)

2. **Check per-table packet counters on the chassis where the LB DNAT
   happens.** For each table in the router pipeline, count how many
   packets match non-default flows:

   ```bash
   for t in $(seq 0 65); do
     result=$(ovs-ofctl dump-flows br-int \
       "table=$t,metadata=0x5" 2>&1 | \
       grep -o "n_packets=[0-9]*" | \
       sed "s/n_packets=//" | \
       awk '{s+=$1} END {print s+0}')
     if [ "$result" != "0" ]; then
       echo "table $t: $result packets"
     fi
   done
   ```

3. **Trace the clone.** After the chassis redirect in table 65, the
   packet enters the switch pipeline as a clone. Track it there too:

   ```bash
   ovs-ofctl dump-flows br-int table=42,metadata=0x3 | \
     grep -v "n_packets=0"
   ```

4. **Check conntrack.** When you suspect a conntrack issue, dump the
   active sessions on the relevant zone:

   ```bash
   conntrack -L -p tcp --dport 80 -zone 12 2>&1
   ```

The clone technique was key: the router `ct_lb` action commits the DNAT,
then `ct_clear` in the clone wipes the conntrack state before the packet
enters the switch pipeline. This is correct behavior — the switch doesn't
need conntrack state. But it means the packet arrives on the remote
chassis fresh, with zero conntrack baggage. And on that remote chassis,
the return path can't find the DNAT entry.

### 9.5 The Fix: Centralized LB on the Gateway Router

The solution is to shift the LB DNAT from the *distributed* router
(`lr-example1`) to the *centralized gateway* router (`gw-r-example1`).
The gateway router is pinned to a single chassis (`ovn-gw`), so both
directions of every connection go through the same OVS conntrack.

The LB is attached to all three relevant logical entities:

```bash
# Keep on the switch for hairpin (same-subnet) traffic
ovn-nbctl ls-lb-add ls-example1-priv lb-example1

# Remove from the distributed router
ovn-nbctl lr-lb-del lr-example1 lb-example1

# Add to the gateway router with skip_snat=true
ovn-nbctl set load_balancer lb-example1 options:skip_snat=true
ovn-nbctl lr-lb-add gw-r-example1 lb-example1
```

`skip_snat=true` prevents the gateway router's SNAT rule from rewriting
the source address of LB-replied packets. Without it, the SNAT rule
`10.0.2.0/24 → 192.168.200.254` would match the VIP (10.0.2.100) after
the reverse DNAT, and the provider would receive a SYN-ACK from
`192.168.200.254` instead of `10.0.2.100`, breaking TCP.

But removing the LB from the distributed router had an unintended
consequence: the VIP ARP responder disappeared from the switch pipeline.
The neighbor advertisement that tells VMs "the MAC for 10.0.2.100 is
`00:00:02:01:00:fe`" is generated by OVN based on the LB's router
attachment. Without it, ARP for the VIP failed:

```
# From ns-priv:
10.0.2.100 dev lsp-priv-srv FAILED
```

All hairpin traffic broke. The final fix was to keep the LB on **all three**
attachments:

| Attachment | Purpose |
|---|---|
| `ls-example1-priv` (switch) | Switch-level LB for hairpin traffic |
| `lr-example1` (distributed router) | VIP ARP responder for the private subnet |
| `gw-r-example1` (gateway router) | Centralized LB DNAT for cross-subnet traffic |

Having the LB on both routers works because of pipeline ordering. When
traffic enters from the provider:

1. `gw-r-example1` processes it first → `lr_in_dnat` matches the VIP
   → NAT commits → dst becomes the backend IP
2. Packet is routed to `lr-example1` → `lr_in_dnat` matches
   `nw_dst=10.0.2.100` — but the dst is now `10.0.2.10` (the backend)
   → flow doesn't fire → packet passes through normally

The conntrack entry lives on the gateway chassis (created by
`gw-r-example1`'s pipeline). The return SYN-ACK hits the compute chassis
first, enters `lr-example1` (which doesn't DNAT because dst is
`192.168.200.10`, not the VIP), then routes through `gw-r-example1` on
the gateway chassis where the conntrack entry exists and the reverse NAT
succeeds.

For hairpin traffic (private → VIP), the packet enters `lr-example1`
directly on the compute chassis. The DNAT and reverse-NAT both happen on
the same chassis, so conntrack works correctly.

### 9.6 Verification

All paths now work end-to-end:

**Cross-subnet LB** (provider → VIP):

```bash
# From ns-provider (192.168.200.10) to VIP:
$ for i in 1 2 3; do
    echo test | nc -w2 10.0.2.100 80
  done
HTTP/1.1 200 OK
HTTP/1.1 200 OK
HTTP/1.1 200 OK
```

The load balancer distributes across backends, alternating between
`backend-10` and `backend-11`.

**Hairpin LB** (private → VIP):

```bash
# From ns-priv (10.0.2.10) to VIP:
$ echo test | nc -w2 10.0.2.100 80
HTTP/1.1 200 OK
backend-11: arch - Tue Jun 30 08:09:00 PM CET 2026
```

**All other traffic still works:** SNAT, east-west direct, ping across
subnets. The LB addition didn't regress anything.

### 9.7 Production Gaps

This setup proves the OVN LB mechanism works, but it's not production-ready:

| Gap | Detail |
|---|---|
| **No health checks** | `health_check: []` in the LB config. A dead backend keeps receiving traffic until someone manually removes it. OVN supports active health monitoring via `ovn-nbctl lb-add --health-check`, but it was not configured. |
| **No session stickiness** | `selection_fields: []`, so OVS uses `dp_hash`. A client reconnecting may hit a different backend. For stateful TCP workloads, this can break sessions. |
| **No application server** | `nc -l -p 80 -e /bin/bash` is a diagnostic toy, not production software. No connection pooling, TLS termination, keepalives, or request logging. |
| **No observability** | Zero metrics: active connections, throughput, error rates, backend health state. OVN exposes some counters via `ovn-sbctl find service_monitor`, but no Prometheus integration or dashboard. |
| **No automation** | The LB config lives in a shell script, managed manually via `ovn-nbctl`. No Terraform, Ansible, or Kubernetes integration. A chassis restart requires re-applying the entire config. |
| **No connection draining** | Removing a backend mid-stream kills TCP connections. No graceful shutdown or drain mechanism. |
| **No weighted routing** | Both backends use `weight:100`. You cannot bias traffic toward a more powerful backend or canary a new version. |
| **Single point of data-plane failure** | Cross-subnet LB is centralized on the gateway router, which is pinned to `ovn-gw`. If that chassis fails, all cross-subnet LB traffic is lost until recovery. |
| **Unhardened** | No rate limiting, connection limits, DDoS protection, or access logging. Any client with network access to the VIP can consume unbounded resources. |

For a real deployment, you would layer a reverse proxy (HAProxy, NGINX,
Envoy) on top of the OVN LB, or use OVN's `Load_Balancer` health checks
and integrate with a service mesh.

## 10. Lessons for a Hyperscaler Mindset

**Use persistent identifiers.** Chassis UUIDs are ephemeral. If you store them
in scripts, they'll break on the first restart. Use chassis names
(`external_ids:hostname`) instead. For production systems, this means your
configuration management must dynamically resolve names to runtime state —
never hardcode UUIDs.

**Understand the router types.** OVN has two kinds of logical routers, and
they compose differently:

- *Distributed router* — data plane runs everywhere, control plane is
  centralized via `ovn-northd`. Use for east-west traffic. Add `gateway-chassis`
  on a port to centralize north-south traffic through a specific node.

- *Gateway router* — fully centralized. Use when all traffic must go through a
  single node (e.g., SNAT, connection to a physical network). Do not add
  `gateway-chassis` to its ports.

Mixing them creates confusing, hard-to-debug states that manifest as unbound
ports and misleading log messages.

**`ovsdb-server` is not `ovn-ctl`.** The `ovn-ctl` wrapper adds assumptions
about hostname resolution that may not match your deployment. For production,
write a direct `ovsdb-server` invocation with explicit IP bindings and
`--db-cluster-local-addr`. Package your start script so it survives reboots
without human intervention.

**RAFT leadership is not sticky.** After a full cluster restart, any node can
become leader. Your tooling must discover the leader dynamically rather than
hardcoding one. For `ovn-nbctl`, always specify `--db=tcp:<any_active_node>:6641`
and handle the "not cluster leader" retry. Better: use `--db=tcp:<leader>:6641`
after probing the cluster status.

**The SB database is the source of truth for runtime state.** When debugging
port binding issues, `ovsdb-client dump tcp:<leader>:6642 OVN_Southbound
Port_Binding` is more useful than any NB command. It shows you exactly which
chassis has claimed each port and what `options` (including `l3gateway-chassis`)
are attached.

## 11. References

- `ovn-architecture(7)` — OVN architecture and design: [Open vSwitch docs](https://docs.ovn.org/en/latest/tutorials/ovn-architecture.html)
- `ovn-nbctl(8)` — OVN Northbound DB management
- `ovsdb-server(1)` — OVSDB server and RAFT cluster configuration
- `ovn-architecture(7)` gateway router vs distributed router: [Gateway Routers](https://docs.ovn.org/en/latest/tutorials/ovn-architecture.html#gateway-routers)
- Open vSwitch releases: [ovs-releases](https://github.com/openvswitch/ovs/tags)
- Debian preseed documentation: [Preseed](https://www.debian.org/releases/stable/amd64/apbs02.en.html)
- libvirt `virt-install` man page: [virt-install(1)](https://man.libvirt.org/virt-install.1.html)
- OVN load balancer documentation: [ovn-nbctl(8) — Load Balancer](https://docs.ovn.org/en/latest/man/ovn-nbctl.8.html#lb-commands)
- OVS conntrack and NAT: [ovs-fields(7)](https://docs.ovn.org/en/latest/man/ovs-fields.7.html)
- Conntrack per-chassis behavior in distributed routers: [ovn-architecture(7) — Distributed NAT](https://docs.ovn.org/en/latest/tutorials/ovn-architecture.html#distributed-nat)
- The session source files (scripts, preseed, verification): `/tmp/opencode/ovn-lab/`
