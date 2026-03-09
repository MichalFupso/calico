# Per-IP Proxy ARP/NDP for Pods and LoadBalancer Services

| Make pods and LB VIPs on the host's L2 subnet directly reachable without BGP by having Felix program per-IP proxy ARP/NDP entries on physical interfaces |  |
| :---- | :---- |
| PMREQ  | |
| EPIC | |
| Author(s) | |
| Timeline | |
| Open source? | Yes (open-source Calico) |
| Release target | |

# Open questions

* Should a FelixConfiguration toggle be added, or should the feature remain always-on with dynamic detection?
* Should `proxy_delay` sysctl be set to 0 automatically on interfaces with proxy ARP entries?

# Approvers

| Approvers | Status | Notes |
| :---- | :---- | :---- |
|  | Not started |  |
|  | Not started |  |

# Background

* When a pod or LoadBalancer VIP is assigned an IP from the same subnet as the node's physical interface, external hosts on that L2 segment try to reach it via ARP. Nobody answers — the pod IP is inside a network namespace behind a veth, and the LB VIP doesn't exist on any interface.
* Today the only way to make these IPs reachable is BGP peering with the upstream router. This requires router configuration and is not always available (flat L2 environments, kind clusters, bare-metal labs, edge deployments).
* Linux supports per-IP proxy ARP (`ip neigh add proxy <IP> dev <iface>`) which makes the node answer ARP only for explicitly registered IPs. This is independent of the blanket `proxy_arp` sysctl which would answer for all routed IPs (including remote pods).
* The equivalent IPv6 mechanism is per-IP proxy NDP, using the same netlink `NTF_PROXY` flag with `AF_INET6`.

#

# ---

# Requirements

* Pods with IPs in the same subnet as a host interface must be reachable from external hosts on that L2 segment without BGP or overlay encapsulation.
* LoadBalancer service VIPs in the same subnet must also be reachable, with exactly one node answering ARP per VIP.
* Both IPv4 (proxy ARP) and IPv6 (proxy NDP) must be supported.
* The feature must not cause the node to answer ARP for IPs belonging to pods on other nodes (no blanket proxy ARP).
* Proxy entries must be cleaned up when pods are deleted, services are removed, or interfaces go away.
* External ARP/neighbor caches must be proactively updated (gratuitous ARP / unsolicited NA) on entry creation to handle pod migration and LB VIP failover.
* The feature must be resilient to external changes to the proxy neighbor table (periodic resync).

#

# ---

# Specification

## Limitations / out-of-scope

* **Single node per LB VIP**: Only one node answers ARP for each LB VIP. There is no active-active HA — if the selected node is down, the VIP is unreachable until the node list updates and hash redistribution selects a new node.
* **Cloud provider ARP filtering**: Some cloud providers (e.g. AWS VPC) filter ARP at the hypervisor level. Proxy ARP will not work unless the VIP/pod IPs are assigned to the node's ENI. This is an infrastructure concern outside Felix's scope.
* **proxy_delay sysctl**: The kernel adds ~800ms delay before responding to proxy ARP. The manager does not currently set this to 0.

## High-level user stories

* Cluster admins can deploy pods with IPs from the same subnet as the host network and have them reachable from external hosts without configuring BGP.
* Cluster admins can create LoadBalancer services with VIPs from the host subnet and have them reachable from the local L2 network.
* The feature works automatically — no user configuration is required. Felix detects subnet overlap dynamically.

## Behavioral changes

* Felix automatically programs per-IP proxy ARP/NDP entries on host physical interfaces when it detects that a local pod IP or a selected LB VIP falls within the same subnet.
* On new entry creation, Felix sends a gratuitous ARP (IPv4) or unsolicited Neighbor Advertisement (IPv6) to proactively update caches on the L2 segment.
* For IPv4 LB VIPs, Felix creates a dummy interface (`cali-lb-arp`) and adds /32 routes to satisfy a kernel requirement (see Technical Design).
* For IPv6, Felix enables the `proxy_ndp` sysctl on interfaces that have proxy NDP entries.
* Entries are removed when pods are deleted, services are removed, or the host interface disappears.

## UI Changes

N/A

## API changes

### User-facing API changes

No new API resources or FelixConfiguration fields are introduced in the initial implementation. The feature is always active and detection is fully dynamic based on subnet overlap.

A future iteration may add a FelixConfiguration toggle (e.g. `proxyARPEnabled`) to allow disabling the feature.

### Frontend API

N/A

### Internal API changes

* A new internal message type `ifaceAddrsCIDRUpdate` is added to the Felix dataplane event loop, carrying interface address changes with CIDR information.
* A new `AddrCIDRStateCallback` is added to the interface monitor alongside the existing `AddrStateCallback`.

## General concerns

### Dataplane support

|  | Supported | Note |
| :---- | :---- | :---- |
| Linux iptables/nftables | Yes | Proxy ARP entries are dataplane-independent (netlink neighbor table) |
| Linux eBPF | Yes | Same — proxy ARP operates at the kernel neighbor table level |
| Windows HNS | No | |

### Platform support

All Linux platforms are supported. The feature operates on standard kernel netlink APIs available on all supported kernel versions. Windows is not supported.

### Monitoring

* Felix logs at Info level when adding/removing proxy ARP entries and when creating the dummy interface.
* Felix logs at Warn level when GARP channel is full (entry is still programmed, only proactive cache update is lost).
* Felix logs at Debug level during resync operations.
* No new Prometheus metrics in the initial implementation. Future: counters for active proxy entries and GARP sends.

### Robustness

* **Node add/delete**: LB VIP hash redistribution happens automatically. The new owner sends GARP to update caches.
* **Felix restart**: On startup, the manager has no cached state. On the first `CompleteDeferredWork` cycle it programs all desired entries from scratch. Periodic `QueueResync` reads back kernel state and reconciles.
* **External interference**: If an external tool flushes proxy entries, the periodic resync (on Felix's route refresh timer) detects the discrepancy and re-programs them.
* **Interface flap**: Interface removal triggers `ifaceAddrsCIDRUpdate` with nil addresses, which removes the interface from tracking. Entries are cleaned up on the next apply cycle.
* **GARP backpressure**: GARP sends are async via a buffered channel (capacity 100). If full, GARP is dropped but the proxy entry is still programmed — subsequent ARP requests will be answered.

### Scale

* **APIserver load**: Zero additional APIserver load. The manager consumes messages already flowing through the Felix calc graph (WorkloadEndpointUpdate, ServiceUpdate, HostMetadata). No new watches or API calls.
* **Per-node cost**: One netlink `NeighSet` call per pod/LB IP that overlaps a host subnet. In typical deployments this is a small number (tens of entries, not thousands).
* **Hash computation**: `selectNodeForIP` sorts hostnames and computes FNV-1a per LB IP per reconciliation cycle. Cost is negligible even at 5000 nodes and hundreds of LB services.

### Troubleshooting

* `ip neigh show proxy` — lists all proxy ARP entries on the node.
* `ip route show dev cali-lb-arp` — shows /32 routes for LB VIPs on the dummy interface.
* `ip -6 neigh show proxy` — lists proxy NDP entries.
* Felix debug logs show all proxy ARP manager decisions (which IPs matched, which entries were added/removed, GARP sends).
* No changes to `calicoctl diags` in the initial implementation. Future: include `ip neigh show proxy` output in diags bundle.

### Install

No installation changes required. The feature is built into Felix and runs automatically. No new deployments, daemonsets, or Helm chart changes.

The dummy interface (`cali-lb-arp`) is created lazily by Felix at runtime when the first LB VIP needs it.

### Licensing

Open-source feature available in all Calico editions.

### Upgrade/Downgrade

* **Upgrade**: No migration needed. On first run after upgrade, Felix programs proxy entries for any existing pods/services that match.
* **Downgrade**: Proxy ARP entries and the dummy interface will remain in the kernel but won't be managed. They will expire naturally or can be cleaned up manually with `ip neigh del proxy` and `ip link del cali-lb-arp`.
* No data format changes or stored state — the manager is purely runtime.

### Version skew

No cross-version compatibility issues. The feature is entirely local to the Felix process on each node. There are no cross-node protocols or shared state beyond the existing calc graph messages.

### Documentation

* How-to guide: deploying pods on the host subnet without BGP using proxy ARP.
* Reference: proxy ARP verification commands (`ip neigh show proxy`, etc.).
* Troubleshooting: common issues (cloud provider ARP filtering, proxy_delay latency).

### Security

* Per-IP proxy ARP is more secure than blanket proxy ARP — the node only answers for explicitly registered IPs, not for all routed IPs.
* The dummy interface and /32 routes are purely local routing tricks with no external attack surface.
* No new APIs, network listeners, or authentication surfaces are introduced.

### RBAC

No RBAC changes. The feature operates entirely within Felix's existing permissions. Felix already has the `NET_ADMIN` capability required for netlink neighbor and route operations.

#

# ---

# Technical Design

The feature is implemented as a single new Felix dataplane manager (`proxyARPManager`) with two instances — one for IPv4 and one for IPv6. It follows the standard Felix manager pattern (`OnUpdate`/`CompleteDeferredWork`).

**Components touched:**
* `felix/dataplane/linux/proxy_arp_mgr.go` — new manager
* `felix/dataplane/linux/int_dataplane.go` — registration, wiring, resync
* `felix/ifacemonitor/iface_monitor.go` — new `AddrCIDRStateCallback`
* `felix/dataplane/linux/dataplanedefs/dataplane_defs.go` — dummy interface constant
* `go.mod` — two new dependencies

**High-level flow:**
```
WorkloadEndpointUpdate ──┐
ServiceUpdate ───────────┤
HostMetadataV4V6Update ──┤──→ OnUpdate() ──→ dirty=true
ifaceAddrsCIDRUpdate ────┘
                                   │
                          CompleteDeferredWork()
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              Pod IPs:       LB VIPs:        Reconcile:
            match subnet   hash select     add/remove
            add entries    node, match     proxy entries
                           subnet, add     and LB routes
                           entries+routes
                                   │
                              Send GARP/UNA
                           for new entries
```

## Pod IP proxy ARP

The hosting node always answers ARP for its own local pods. No cross-node coordination is needed — if the pod is local, this node answers.

### Input: WorkloadEndpointUpdate

The manager learns pod IPs from `WorkloadEndpointUpdate` protobuf messages fanned out by the internal dataplane. Each message carries the pod's assigned IPs in `Ipv4Nets` (e.g. `["172.16.101.49/32"]`) or `Ipv6Nets` fields. The manager stores them keyed by a composite workload key (`orchestratorId/workloadId/endpointId`).

When a `WorkloadEndpointRemove` arrives, the corresponding IPs are deleted from the map and the `dirty` flag is set, triggering reconciliation.

### Input: ifaceAddrsCIDRUpdate

The manager learns host interface subnets from `ifaceAddrsCIDRUpdate` messages produced by the interface monitor. These arrive when interface addresses change (add/remove/modify).

The interface monitor's local route table entries are `/32` host-scope routes, which don't preserve the real subnet prefix length. The manager uses the message as a trigger but queries `nlHandle.AddrList()` via netlink directly to obtain the actual `IPNet` with the correct prefix (e.g. `172.16.101.102/24` rather than `172.16.101.102/32`). This is necessary to determine whether a pod IP falls within the same L2 broadcast domain.

Workload interfaces (matching the `cali*` prefix regex) are filtered out — only physical/non-workload host interfaces are tracked.

### Matching logic

On each `CompleteDeferredWork` cycle, the manager iterates all local workload IPs and checks each against all known host interface subnets:

```
for each workload IP (e.g. 172.16.101.49):
    for each host interface (e.g. eth0 → 172.16.101.102/24):
        if the /24 subnet contains 172.16.101.49:
            desired[proxyARPEntry{ifaceName: "eth0", podIP: "172.16.101.49"}] = true
```

If a pod IP doesn't fall within any host interface subnet, no proxy entry is created. This is the common case for pods using a different CIDR than the host network — the feature is effectively a no-op.

### Why no additional routing is needed

Pod IPs already have /32 routes via their cali* veth interfaces, created by Felix's endpoint manager:

```
172.16.101.49 dev cali75a92f45e54 scope link
```

The kernel's per-IP proxy ARP check (`rt->dst.dev != dev` in `net/ipv4/arp.c`) is naturally satisfied because the route points to the cali* veth (not eth0). This is unlike LB VIPs which require a dummy interface workaround.

### Gratuitous ARP on creation

When a new proxy entry is added (not already in `activeProxyEntries`), a gratuitous ARP request is queued to the async `garpWorker` goroutine. The GARP is sent on the host interface (e.g. eth0) with the pod IP as both sender and target, broadcast to `ff:ff:ff:ff:ff:ff`. This proactively updates ARP caches on all hosts in the L2 domain.

This is particularly important for pod migration — when a pod with a static IP moves from node A to node B, node B's GARP updates external ARP caches to point to node B's MAC, avoiding stale entries that would black-hole traffic until cache expiry.

## LoadBalancer VIP proxy ARP

### Node selection

For each LB VIP, exactly one node must answer ARP. The manager builds a sorted list of all cluster node hostnames (from `HostMetadataV4V6Update`) and uses FNV-1a hash of the IP string modulo node count to select a node. This is deterministic — all nodes compute the same result. When nodes join or leave, some VIPs get redistributed.

### Dummy interface for IPv4

The Linux kernel's per-IP proxy ARP code path (`net/ipv4/arp.c:arp_process`) checks `rt->dst.dev != dev` before honoring a proxy entry. The route for the target IP must go through a different interface than where the ARP arrived.

Pod IPs satisfy this naturally (route via cali* veth != eth0). LB VIPs do not — they match the broad subnet route on eth0, so `rt->dst.dev == dev` and the proxy entry is silently ignored.

The fix: create a dummy interface (`cali-lb-arp`) and add /32 routes for each LB VIP. This makes the route resolve to the dummy interface, satisfying the kernel check. No traffic flows through the dummy — real service traffic arrives on eth0 and is DNAT'd by kube-proxy to backend pods.

The dummy interface is listed in the route table syncer's `NonManagedInterfaces` to prevent Felix from claiming its routes.

### IPv6 LB VIPs do not need the dummy

The IPv6 NDP proxy path (`net/ipv6/ndisc.c:ndisc_recv_ns`) does not have the `rt->dst.dev != dev` check. It only requires `proxy_ndp=1` sysctl and a per-IP entry. No dummy interface or /128 routes are needed for IPv6.

## IPv6 proxy NDP specifics

* The `proxy_ndp` sysctl must be enabled per-interface (`/proc/sys/net/ipv6/conf/<iface>/proxy_ndp=1`). The manager enables it when an interface gets its first proxy NDP entry.
* Cache updates use Unsolicited Neighbor Advertisements (Override=true, Solicited=false) sent to `ff02::1`.
* Uses the `mdlayher/ndp` library for raw ICMPv6 NDP messages.

## Resync mechanism

The manager supports `QueueResync()`, called on Felix's periodic route refresh timer. It reads the actual proxy entries from the kernel via `NeighList` (filtering for `NTF_PROXY` flag) and routes from the dummy interface, then reconciles against desired state — re-adding flushed entries and removing stale ones.

## General considerations

### Open-source / enterprise

This is an open-source feature. All code lives in the `projectcalico/calico` repository. No enterprise-only components.

### Testing

**Unit tests** (Ginkgo v2, `proxy_arp_mgr_test.go`):
* Pod IP proxy ARP: basic enable, workload removal, multiple pods/interfaces, subnet mismatch, interface filtering, race conditions (workload before/after interface CIDR), no duplicate GARP, interface removal
* LoadBalancer IPs: selected/non-selected node, service removal, node add/remove causing hash redistribution, non-LB service type ignored, LB IP outside subnet, multiple LB services, deprecated `loadbalancer_ip` field, pod+LB coexistence, deterministic hash, type change (LB to ClusterIP)
* LB dummy routes: route added/removed for selected/non-selected, pod IPs don't get routes, route cleanup on service/node changes, multiple services, resync after external flush, coexistence with pod IPs
* IPv6: basic proxy NDP, unsolicited NA sent, `proxy_ndp` sysctl enabled, IPv4 filtered in IPv6 manager, multiple pods
* Resync: flushed entries re-created, stale entries removed, no-op when kernel matches, partial interface resync, LB+pod coexistence resync

**FV tests**: To be added — test proxy ARP in a multi-node kind cluster with pods and LB services on the host subnet, verifying reachability from an external container.

**Scale testing**: Not required for initial delivery. The feature adds O(local pods + selected LB VIPs) netlink calls per reconciliation, which is bounded and small.

### Infrastructure Automation (Banzai)

No Banzai changes required. The feature is part of the core Felix binary and requires no special cluster provisioning or environment targeting.

## Security Considerations

### Security Controls

No new security controls needed. The feature uses existing Felix capabilities (`NET_ADMIN` for netlink operations). No new APIs or network endpoints are exposed.

### Data handling

No sensitive data is stored or transmitted. The feature only programs kernel neighbor table entries and routes using IP addresses already known to Felix.

### Attack Surface

* Per-IP proxy ARP is strictly narrower than blanket proxy ARP — the node only answers for IPs it explicitly registers.
* An attacker with access to create pods or LB services could cause the node to answer ARP for those IPs, but this is the intended behavior and is constrained by Kubernetes RBAC on pod/service creation.
* The dummy interface has no external attack surface — it carries no traffic.

## Multi-cluster management and Calico Cloud

### Data storage changes

N/A — no new data storage. The feature is purely runtime state in the Felix process.

### Management cluster changes

N/A

### Managed cluster changes

N/A — Felix is already deployed as part of the calico-node daemonset. No new components.

### Global Ops cluster changes

N/A
