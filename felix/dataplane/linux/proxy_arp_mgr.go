// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intdataplane

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/j-keck/arping"
	"github.com/mdlayher/ndp"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// proxyARPEntry represents a per-IP proxy ARP neighbor entry on a specific host interface.
// This is equivalent to: ip neigh add proxy <podIP> dev <ifaceName>
type proxyARPEntry struct {
	ifaceName string
	podIP     string
}

// proxyARPManager automatically adds per-IP proxy ARP neighbor entries on host physical
// interfaces when local pods have IPs that fall within the same L2 subnet as the host
// interface. This allows pods to be directly reachable on the physical network without
// BGP or overlay encapsulation, while only responding to ARP for specific pod IPs rather
// than enabling blanket proxy ARP on the interface.
//
// The manager uses WorkloadEndpointUpdate messages to learn pod IPs. The subnet overlap
// between pod IPs and host interface CIDRs is the sole criterion for programming proxy
// ARP entries — no IPAM pool encapsulation mode check is required.
type proxyARPManager struct {
	ipVersion      uint8
	wlIfacesRegexp *regexp.Regexp

	// hostIfaceToCIDRs maps host interface name to the parsed CIDRs on that interface.
	hostIfaceToCIDRs map[string][]net.IPNet

	// localWorkloadIPs maps workload endpoint key to the pod's IP strings.
	// Key is "orchestratorID/workloadID/endpointID".
	localWorkloadIPs map[string][]string

	// activeProxyEntries tracks which proxy ARP entries are currently programmed.
	activeProxyEntries map[proxyARPEntry]bool

	dirty    bool
	nlHandle netlinkshim.Interface
	sendGARP garpSenderFunc

	// garpC is a channel for async GARP sends.
	garpC  chan garpRequest
	cancel context.CancelFunc
}

type garpRequest struct {
	ifaceName string
	podIP     net.IP
}

type garpSenderFunc func(ifaceName string, podIP net.IP) error

func newProxyARPManager(
	dpConfig Config,
	ipVersion uint8,
) *proxyARPManager {
	nl, _ := netlinkshim.NewRealNetlink()
	var sender garpSenderFunc
	if ipVersion == 6 {
		sender = sendUnsolicitedNA
	} else {
		sender = sendGratuitousARP
	}
	return newProxyARPManagerWithShims(dpConfig, ipVersion, nl, sender)
}

func newProxyARPManagerWithShims(
	dpConfig Config,
	ipVersion uint8,
	nl netlinkshim.Interface,
	garpSender garpSenderFunc,
) *proxyARPManager {
	wlIfacesPattern := "^(" + strings.Join(dpConfig.RulesConfig.WorkloadIfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	ctx, cancel := context.WithCancel(context.Background())
	m := &proxyARPManager{
		ipVersion:          ipVersion,
		wlIfacesRegexp:     wlIfacesRegexp,
		hostIfaceToCIDRs:   make(map[string][]net.IPNet),
		localWorkloadIPs:   make(map[string][]string),
		activeProxyEntries: make(map[proxyARPEntry]bool),
		nlHandle:           nl,
		sendGARP:           garpSender,
		garpC:              make(chan garpRequest, 100),
		cancel:             cancel,
	}
	go m.garpWorker(ctx)
	return m
}

func (m *proxyARPManager) OnUpdate(protoBufMsg any) {
	switch msg := protoBufMsg.(type) {
	case *ifaceAddrsCIDRUpdate:
		if m.wlIfacesRegexp.MatchString(msg.Name) {
			return
		}
		log.WithFields(log.Fields{
			"ifaceName": msg.Name,
			"addrCIDRs": msg.AddrCIDRs,
		}).Debug("Proxy ARP manager received ifaceAddrsCIDRUpdate")
		m.updateHostIfaceCIDRs(msg.Name, msg.AddrCIDRs)
		m.dirty = true

	case *proto.WorkloadEndpointUpdate:
		ep := msg.GetEndpoint()
		if ep == nil || msg.GetId() == nil {
			return
		}
		wlKey := workloadEndpointKey(msg.GetId())
		var ips []string
		if m.ipVersion == 4 {
			ips = ep.Ipv4Nets
		} else {
			ips = ep.Ipv6Nets
		}
		log.WithFields(log.Fields{
			"workload": wlKey,
			"ips":      ips,
		}).Debug("Proxy ARP manager received WorkloadEndpointUpdate")
		if len(ips) > 0 {
			m.localWorkloadIPs[wlKey] = ips
		} else {
			delete(m.localWorkloadIPs, wlKey)
		}
		m.dirty = true

	case *proto.WorkloadEndpointRemove:
		if msg.GetId() == nil {
			return
		}
		wlKey := workloadEndpointKey(msg.GetId())
		if _, ok := m.localWorkloadIPs[wlKey]; ok {
			log.WithField("workload", wlKey).Debug("Proxy ARP manager received WorkloadEndpointRemove")
			delete(m.localWorkloadIPs, wlKey)
			m.dirty = true
		}
	}
}

func (m *proxyARPManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}
	m.dirty = false

	log.WithFields(log.Fields{
		"numWorkloads":  len(m.localWorkloadIPs),
		"numHostIfaces": len(m.hostIfaceToCIDRs),
	}).Debug("Proxy ARP manager CompleteDeferredWork")

	// Build desired state: which (interface, podIP) pairs need proxy ARP entries.
	desired := make(map[proxyARPEntry]bool)

	for _, ipNets := range m.localWorkloadIPs {
		for _, ipNet := range ipNets {
			podIP := parsePodIP(ipNet)
			if podIP == nil {
				continue
			}
			for ifaceName, cidrs := range m.hostIfaceToCIDRs {
				for _, cidr := range cidrs {
					if cidr.Contains(podIP) {
						desired[proxyARPEntry{ifaceName: ifaceName, podIP: podIP.String()}] = true
						break
					}
				}
			}
		}
	}

	// Add new proxy ARP entries and send GARP for newly-appearing pods.
	for entry := range desired {
		if !m.activeProxyEntries[entry] {
			m.addProxyARPEntry(entry)
			podIP := net.ParseIP(entry.podIP)
			if podIP != nil {
				select {
				case m.garpC <- garpRequest{ifaceName: entry.ifaceName, podIP: podIP}:
				default:
					log.WithFields(log.Fields{
						"iface": entry.ifaceName,
						"podIP": entry.podIP,
					}).Warn("GARP channel full, dropping gratuitous ARP send")
				}
			}
		}
	}

	// Remove stale proxy ARP entries.
	for entry := range m.activeProxyEntries {
		if !desired[entry] {
			m.removeProxyARPEntry(entry)
		}
	}

	m.activeProxyEntries = desired
	return nil
}

func (m *proxyARPManager) updateHostIfaceCIDRs(ifaceName string, addrCIDRs set.Set[string]) {
	if addrCIDRs == nil {
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	// The ifaceAddrsCIDRUpdate comes from the interface monitor's local route table,
	// which has /32 host-scope entries. We need the actual subnet prefix from the
	// interface address (e.g., /24) to determine if a pod IP falls within the same
	// L2 subnet. Query the interface addresses directly via netlink.
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to look up interface for CIDR update")
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	family := netlink.FAMILY_V4
	if m.ipVersion == 6 {
		family = netlink.FAMILY_V6
	}

	addrs, err := m.nlHandle.AddrList(link, family)
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to list addresses for interface")
		delete(m.hostIfaceToCIDRs, ifaceName)
		return
	}

	var cidrs []net.IPNet
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		cidrs = append(cidrs, *addr.IPNet)
	}

	log.WithFields(log.Fields{
		"iface": ifaceName,
		"cidrs": cidrs,
	}).Debug("Proxy ARP manager updated host interface CIDRs from AddrList")

	if len(cidrs) > 0 {
		m.hostIfaceToCIDRs[ifaceName] = cidrs
	} else {
		delete(m.hostIfaceToCIDRs, ifaceName)
	}
}

// addProxyARPEntry adds a per-IP proxy ARP neighbor entry on the given interface.
// Equivalent to: ip neigh add proxy <podIP> dev <ifaceName>
func (m *proxyARPManager) addProxyARPEntry(entry proxyARPEntry) {
	logCtx := log.WithFields(log.Fields{
		"iface": entry.ifaceName,
		"podIP": entry.podIP,
	})

	link, err := m.nlHandle.LinkByName(entry.ifaceName)
	if err != nil {
		logCtx.WithError(err).Warn("Failed to look up interface for proxy ARP entry")
		return
	}

	family := unix.AF_INET
	if m.ipVersion == 6 {
		family = unix.AF_INET6
	}

	neigh := &netlink.Neigh{
		Family:    family,
		LinkIndex: link.Attrs().Index,
		Flags:     netlink.NTF_PROXY,
		IP:        net.ParseIP(entry.podIP),
	}

	logCtx.Info("Adding per-IP proxy ARP entry")
	if err := m.nlHandle.NeighSet(neigh); err != nil {
		logCtx.WithError(err).Warn("Failed to add proxy ARP neighbor entry")
	}
}

// removeProxyARPEntry removes a per-IP proxy ARP neighbor entry from the given interface.
// Equivalent to: ip neigh del proxy <podIP> dev <ifaceName>
func (m *proxyARPManager) removeProxyARPEntry(entry proxyARPEntry) {
	logCtx := log.WithFields(log.Fields{
		"iface": entry.ifaceName,
		"podIP": entry.podIP,
	})

	link, err := m.nlHandle.LinkByName(entry.ifaceName)
	if err != nil {
		logCtx.WithError(err).Debug("Failed to look up interface for proxy ARP entry removal (interface may be gone)")
		return
	}

	family := unix.AF_INET
	if m.ipVersion == 6 {
		family = unix.AF_INET6
	}

	neigh := &netlink.Neigh{
		Family:    family,
		LinkIndex: link.Attrs().Index,
		Flags:     netlink.NTF_PROXY,
		IP:        net.ParseIP(entry.podIP),
	}

	logCtx.Info("Removing per-IP proxy ARP entry")
	if err := m.nlHandle.NeighDel(neigh); err != nil {
		logCtx.WithError(err).Debug("Failed to remove proxy ARP neighbor entry (may already be gone)")
	}
}

func (m *proxyARPManager) garpWorker(ctx context.Context) {
	for {
		select {
		case req := <-m.garpC:
			if err := m.sendGARP(req.ifaceName, req.podIP); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"iface": req.ifaceName,
					"podIP": req.podIP,
				}).Warn("Failed to send gratuitous ARP")
			}
		case <-ctx.Done():
			return
		}
	}
}

// workloadEndpointKey returns a stable string key for a WorkloadEndpointID.
func workloadEndpointKey(id *proto.WorkloadEndpointID) string {
	return id.OrchestratorId + "/" + id.WorkloadId + "/" + id.EndpointId
}

// parsePodIP extracts the IP address from a CIDR string like "10.0.0.50/32".
func parsePodIP(cidrStr string) net.IP {
	ipStr := cidrStr
	if idx := strings.IndexByte(cidrStr, '/'); idx >= 0 {
		ipStr = cidrStr[:idx]
	}
	return net.ParseIP(ipStr)
}

// sendGratuitousARP sends a gratuitous ARP announcement for the given IP on the given interface.
// A gratuitous ARP is an ARP request where sender IP == target IP, sent to the broadcast MAC
// address. This updates ARP caches on all hosts in the L2 domain.
func sendGratuitousARP(ifaceName string, podIP net.IP) error {
	return arping.GratuitousArpOverIfaceByName(podIP, ifaceName)
}

// sendUnsolicitedNA sends an unsolicited Neighbor Advertisement for the given IPv6 address
// on the given interface. This is the IPv6 equivalent of a gratuitous ARP: an NA with
// Solicited=false and Override=true, sent to the all-nodes multicast address ff02::1.
// It updates neighbor caches on all IPv6 hosts in the L2 domain.
func sendUnsolicitedNA(ifaceName string, podIP net.IP) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}

	addr, ok := netip.AddrFromSlice(podIP)
	if !ok {
		return fmt.Errorf("invalid IP address: %s", podIP)
	}

	conn, _, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("failed to create NDP connection on %s: %w", ifaceName, err)
	}
	defer func() { _ = conn.Close() }()

	na := &ndp.NeighborAdvertisement{
		Override:      true,
		TargetAddress: addr,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      iface.HardwareAddr,
			},
		},
	}

	// ff02::1 is the all-nodes link-local multicast address. All IPv6 hosts on
	// the L2 segment receive this, analogous to broadcast in IPv4 gratuitous ARP.
	allNodesMulticast := netip.MustParseAddr("ff02::1")
	if err := conn.WriteTo(na, nil, allNodesMulticast); err != nil {
		return fmt.Errorf("failed to send unsolicited NA for %s on %s: %w", podIP, ifaceName, err)
	}
	return nil
}
