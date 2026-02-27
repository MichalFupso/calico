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
	"fmt"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// mockNetlinkForProxyARP tracks proxy ARP neighbor add/del operations.
type mockNetlinkForProxyARP struct {
	netlinkshimStub
	mu          sync.Mutex
	proxyNeighs map[proxyARPEntry]bool // currently programmed entries
	links       map[string]*netlink.Dummy
	// ifaceAddrs maps interface name to the addresses that AddrList should return.
	ifaceAddrs map[string][]netlink.Addr
	// routes tracks routes added via RouteReplace, keyed by "linkIdx:dst".
	routes map[string]netlink.Route
}

// netlinkshimStub provides default no-op implementations for the netlink interface.
// Only methods used by proxyARPManager are overridden in mockNetlinkForProxyARP.
type netlinkshimStub struct{}

func (s netlinkshimStub) LinkByName(name string) (netlink.Link, error) { return nil, nil }
func (s netlinkshimStub) LinkList() ([]netlink.Link, error)            { return nil, nil }
func (s netlinkshimStub) LinkAdd(link netlink.Link) error              { return nil }
func (s netlinkshimStub) LinkDel(link netlink.Link) error              { return nil }
func (s netlinkshimStub) LinkSetMTU(link netlink.Link, mtu int) error  { return nil }
func (s netlinkshimStub) LinkSetUp(link netlink.Link) error            { return nil }
func (s netlinkshimStub) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return nil, nil
}
func (s netlinkshimStub) AddrAdd(link netlink.Link, addr *netlink.Addr) error { return nil }
func (s netlinkshimStub) AddrDel(link netlink.Link, addr *netlink.Addr) error { return nil }
func (s netlinkshimStub) RuleList(family int) ([]netlink.Rule, error)         { return nil, nil }
func (s netlinkshimStub) RuleAdd(rule *netlink.Rule) error                    { return nil }
func (s netlinkshimStub) RuleDel(rule *netlink.Rule) error                    { return nil }
func (s netlinkshimStub) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (s netlinkshimStub) RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, f func(netlink.Route) (cont bool)) error {
	return nil
}
func (s netlinkshimStub) RouteAdd(route *netlink.Route) error                      { return nil }
func (s netlinkshimStub) RouteDel(route *netlink.Route) error                      { return nil }
func (s netlinkshimStub) RouteReplace(route *netlink.Route) error                  { return nil }
func (s netlinkshimStub) NeighList(linkIndex, family int) ([]netlink.Neigh, error) { return nil, nil }
func (s netlinkshimStub) NeighAdd(neigh *netlink.Neigh) error                      { return nil }
func (s netlinkshimStub) NeighSet(neigh *netlink.Neigh) error                      { return nil }
func (s netlinkshimStub) NeighDel(neigh *netlink.Neigh) error                      { return nil }
func (s netlinkshimStub) Delete()                                                  {}
func (s netlinkshimStub) SetSocketTimeout(to time.Duration) error                  { return nil }
func (s netlinkshimStub) SetStrictCheck(v bool) error                              { return nil }

func newMockNetlinkForProxyARP() *mockNetlinkForProxyARP {
	return &mockNetlinkForProxyARP{
		proxyNeighs: make(map[proxyARPEntry]bool),
		links: map[string]*netlink.Dummy{
			"eth0": {LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "eth0"}},
			"eth1": {LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth1"}},
		},
		ifaceAddrs: make(map[string][]netlink.Addr),
		routes:     make(map[string]netlink.Route),
	}
}

func (m *mockNetlinkForProxyARP) LinkByName(name string) (netlink.Link, error) {
	if link, ok := m.links[name]; ok {
		return link, nil
	}
	return nil, net.UnknownNetworkError(name)
}

func (m *mockNetlinkForProxyARP) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	name := link.Attrs().Name
	if addrs, ok := m.ifaceAddrs[name]; ok {
		return addrs, nil
	}
	return nil, nil
}

func (m *mockNetlinkForProxyARP) NeighSet(neigh *netlink.Neigh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if neigh.Flags&netlink.NTF_PROXY != 0 {
		ifaceName := m.ifaceNameByIndex(neigh.LinkIndex)
		m.proxyNeighs[proxyARPEntry{ifaceName: ifaceName, podIP: neigh.IP.String()}] = true
	}
	return nil
}

func (m *mockNetlinkForProxyARP) NeighDel(neigh *netlink.Neigh) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if neigh.Flags&netlink.NTF_PROXY != 0 {
		ifaceName := m.ifaceNameByIndex(neigh.LinkIndex)
		delete(m.proxyNeighs, proxyARPEntry{ifaceName: ifaceName, podIP: neigh.IP.String()})
	}
	return nil
}

func (m *mockNetlinkForProxyARP) ifaceNameByIndex(idx int) string {
	for name, link := range m.links {
		if link.Attrs().Index == idx {
			return name
		}
	}
	return ""
}

func (m *mockNetlinkForProxyARP) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []netlink.Neigh
	ifaceName := m.ifaceNameByIndex(linkIndex)
	for entry := range m.proxyNeighs {
		if entry.ifaceName == ifaceName {
			result = append(result, netlink.Neigh{
				LinkIndex: linkIndex,
				Family:    family,
				Flags:     netlink.NTF_PROXY,
				IP:        net.ParseIP(entry.podIP),
			})
		}
	}
	return result, nil
}

func (m *mockNetlinkForProxyARP) getEntries() map[proxyARPEntry]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[proxyARPEntry]bool)
	for k, v := range m.proxyNeighs {
		result[k] = v
	}
	return result
}

// flushEntries simulates an external actor flushing all proxy ARP entries from the kernel.
func (m *mockNetlinkForProxyARP) flushEntries() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyNeighs = make(map[proxyARPEntry]bool)
}

// injectEntry simulates an external actor adding a proxy ARP entry to the kernel.
func (m *mockNetlinkForProxyARP) injectEntry(ifaceName, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyNeighs[proxyARPEntry{ifaceName: ifaceName, podIP: ip}] = true
}

func (m *mockNetlinkForProxyARP) LinkAdd(link netlink.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := link.Attrs().Name
	if _, ok := m.links[name]; ok {
		return fmt.Errorf("link %s already exists", name)
	}
	// Assign a unique index.
	maxIdx := 0
	for _, l := range m.links {
		if l.Attrs().Index > maxIdx {
			maxIdx = l.Attrs().Index
		}
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: maxIdx + 1, Name: name}}
	m.links[name] = dummy
	return nil
}

func (m *mockNetlinkForProxyARP) LinkSetUp(link netlink.Link) error {
	return nil
}

func (m *mockNetlinkForProxyARP) RouteReplace(route *netlink.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d:%s", route.LinkIndex, route.Dst)
	m.routes[key] = *route
	return nil
}

func (m *mockNetlinkForProxyARP) RouteDel(route *netlink.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d:%s", route.LinkIndex, route.Dst)
	if _, ok := m.routes[key]; !ok {
		return fmt.Errorf("route %s not found", key)
	}
	delete(m.routes, key)
	return nil
}

func (m *mockNetlinkForProxyARP) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []netlink.Route
	for _, r := range m.routes {
		if filterMask&netlink.RT_FILTER_OIF != 0 && r.LinkIndex != filter.LinkIndex {
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

// getRoutes returns a copy of the current routes map.
func (m *mockNetlinkForProxyARP) getRoutes() map[string]netlink.Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]netlink.Route, len(m.routes))
	for k, v := range m.routes {
		result[k] = v
	}
	return result
}

// getRouteIPs returns the set of destination IP strings from all tracked routes.
func (m *mockNetlinkForProxyARP) getRouteIPs() set.Set[string] {
	m.mu.Lock()
	defer m.mu.Unlock()
	ips := set.New[string]()
	for _, r := range m.routes {
		if r.Dst != nil {
			ips.Add(r.Dst.IP.String())
		}
	}
	return ips
}

// flushRoutes simulates an external actor removing all routes from the dummy interface.
func (m *mockNetlinkForProxyARP) flushRoutes() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes = make(map[string]netlink.Route)
}

// setIfaceAddr configures the mock to return the given CIDR when AddrList is called
// for the specified interface.
func (m *mockNetlinkForProxyARP) setIfaceAddr(ifaceName string, cidrStr string) {
	ipAddr, ipNet, _ := net.ParseCIDR(cidrStr)
	ipNet.IP = ipAddr
	m.ifaceAddrs[ifaceName] = []netlink.Addr{{IPNet: ipNet}}
}

type mockGARPSender struct {
	mu    sync.Mutex
	calls []garpCall
}

type garpCall struct {
	ifaceName string
	podIP     string
}

func newMockGARPSender() *mockGARPSender {
	return &mockGARPSender{}
}

func (m *mockGARPSender) send(ifaceName string, podIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, garpCall{ifaceName: ifaceName, podIP: podIP.String()})
	return nil
}

func (m *mockGARPSender) getCalls() []garpCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]garpCall, len(m.calls))
	copy(result, m.calls)
	return result
}

func (m *mockGARPSender) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func newTestProxyARPManager(nl *mockNetlinkForProxyARP, garpSender *mockGARPSender) *proxyARPManager {
	return newTestProxyARPManagerWithHostname(nl, garpSender, "test-node")
}

func newTestProxyARPManagerWithHostname(nl *mockNetlinkForProxyARP, garpSender *mockGARPSender, hostname string) *proxyARPManager {
	config := Config{
		Hostname: hostname,
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	return newProxyARPManagerWithShims(config, 4, nl, garpSender.send, noopProcSysWriter)
}

func noopProcSysWriter(_, _ string) error {
	return nil
}

func svcUpdate(name, namespace, svcType string, ingressIPs ...string) *proto.ServiceUpdate {
	return &proto.ServiceUpdate{
		Name:                   name,
		Namespace:              namespace,
		Type:                   svcType,
		LoadbalancerIngressIps: ingressIPs,
	}
}

func svcRemove(name, namespace string) *proto.ServiceRemove {
	return &proto.ServiceRemove{
		Name:      name,
		Namespace: namespace,
	}
}

func sendHostMetadata(mgr *proxyARPManager, hostname, ipv4Addr string) {
	mgr.OnUpdate(&proto.HostMetadataV4V6Update{
		Hostname: hostname,
		Ipv4Addr: ipv4Addr,
	})
}

func sendHostMetadataRemove(mgr *proxyARPManager, hostname string) {
	mgr.OnUpdate(&proto.HostMetadataV4V6Remove{
		Hostname: hostname,
	})
}

// Helper to create a WorkloadEndpointUpdate.
func wepUpdate(orchID, wlID, epID string, ipv4Nets ...string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets: ipv4Nets,
		},
	}
}

// Helper to create a WorkloadEndpointRemove.
func wepRemove(orchID, wlID, epID string) *proto.WorkloadEndpointRemove {
	return &proto.WorkloadEndpointRemove{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
	}
}

func sendIfaceCIDRUpdate(mgr *proxyARPManager, name string, cidrs ...string) {
	mgr.OnUpdate(&ifaceAddrsCIDRUpdate{
		Name:      name,
		AddrCIDRs: set.FromArray(cidrs),
	})
}

var _ = Describe("Proxy ARP manager", func() {
	var (
		mgr        *proxyARPManager
		nl         *mockNetlinkForProxyARP
		garpSender *mockGARPSender
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyARP()
		garpSender = newMockGARPSender()
		mgr = newTestProxyARPManager(nl, garpSender)
	})

	AfterEach(func() {
		mgr.cancel()
	})

	Describe("basic enable", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add a proxy ARP entry for the pod IP on eth0", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
		})

		It("should send GARP", func() {
			Eventually(func() []garpCall {
				return garpSender.getCalls()
			}).Should(ContainElement(garpCall{ifaceName: "eth0", podIP: "10.0.0.50"}))
		})
	})

	Describe("workload removed", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))

			// Remove the workload endpoint.
			mgr.OnUpdate(wepRemove("k8s", "default/pod1", "eth0"))
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should remove the proxy ARP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("multiple pods same interface", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(wepUpdate("k8s", "default/pod2", "eth0", "10.0.0.51/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add proxy ARP entries for both pods", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(2))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.51"}))
		})

		Context("after removing one pod", func() {
			BeforeEach(func() {
				mgr.OnUpdate(wepRemove("k8s", "default/pod1", "eth0"))
				err := mgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should still have the other pod's entry", func() {
				entries := nl.getEntries()
				Expect(entries).To(HaveLen(1))
				Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.51"}))
			})
		})

		Context("after removing both pods", func() {
			BeforeEach(func() {
				mgr.OnUpdate(wepRemove("k8s", "default/pod1", "eth0"))
				mgr.OnUpdate(wepRemove("k8s", "default/pod2", "eth0"))
				err := mgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have no proxy ARP entries", func() {
				Expect(nl.getEntries()).To(BeEmpty())
			})
		})
	})

	Describe("multiple interfaces", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			nl.setIfaceAddr("eth1", "192.168.1.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			sendIfaceCIDRUpdate(mgr, "eth1", "192.168.1.1/32")
			// Pod in eth0's subnet only.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add proxy ARP entry only on eth0", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(1))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
		})
	})

	Describe("no match - pod outside any host subnet", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("workload interface filtered", func() {
		BeforeEach(func() {
			sendIfaceCIDRUpdate(mgr, "cali12345", "10.0.0.50/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("race: workload arrives before interface CIDR", func() {
		BeforeEach(func() {
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy ARP entries yet", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})

		Context("after interface CIDR arrives", func() {
			BeforeEach(func() {
				nl.setIfaceAddr("eth0", "10.0.0.1/24")
				sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
				err := mgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should now add the proxy ARP entry", func() {
				entries := nl.getEntries()
				Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			})
		})
	})

	Describe("race: interface CIDR arrives before workload", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy ARP entries yet", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})

		Context("after workload arrives", func() {
			BeforeEach(func() {
				mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
				err := mgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should now add the proxy ARP entry", func() {
				entries := nl.getEntries()
				Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			})
		})
	})

	Describe("GARP not sent for existing pods on second reconciliation", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() int {
				return len(garpSender.getCalls())
			}).Should(Equal(1))

			// Reset and trigger another reconciliation without changes.
			garpSender.reset()
			mgr.dirty = true
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not send duplicate GARP", func() {
			Consistently(func() int {
				return len(garpSender.getCalls())
			}).Should(Equal(0))
		})
	})

	Describe("interface removed", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))

			// Interface removed (nil CIDRs).
			mgr.OnUpdate(&ifaceAddrsCIDRUpdate{Name: "eth0", AddrCIDRs: nil})
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should remove the proxy ARP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("IPv6 addresses filtered in IPv4 manager", func() {
		BeforeEach(func() {
			sendIfaceCIDRUpdate(mgr, "eth0", "fd00::1/64")
			mgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "default/pod1",
					EndpointId:     "eth0",
				},
				Endpoint: &proto.WorkloadEndpoint{
					Ipv6Nets: []string{"fd00::50/128"},
				},
			})
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})
})

var _ = Describe("Proxy ARP manager - LoadBalancer IPs", func() {
	var (
		mgr        *proxyARPManager
		nl         *mockNetlinkForProxyARP
		garpSender *mockGARPSender
	)

	// With nodes ["node-a","node-b","node-c"], FNV-1a hash selects:
	//   "10.0.0.100" -> node-c (idx 2)
	//   "10.0.0.101" -> node-a (idx 0)
	//   "10.0.0.102" -> node-b (idx 1)

	setupThreeNodes := func(mgr *proxyARPManager) {
		sendHostMetadata(mgr, "node-a", "1.1.1.1")
		sendHostMetadata(mgr, "node-b", "1.1.1.2")
		sendHostMetadata(mgr, "node-c", "1.1.1.3")
	}

	Describe("LB IP on selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" hashes to node-c with 3 nodes.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should add a proxy ARP entry", func() {
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})

		It("should send GARP", func() {
			Eventually(func() []garpCall {
				return garpSender.getCalls()
			}).Should(ContainElement(garpCall{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("LB IP on non-selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" hashes to node-c, but we are node-a.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add a proxy ARP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("service removed cleans up entry", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(HaveLen(1))

			mgr.OnUpdate(svcRemove("my-svc", "default"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove the proxy ARP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("node added causes re-evaluation", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// With 2 nodes ["node-a","node-b"], "10.0.0.100" hashes to node-b (idx 1).
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-b")
			sendHostMetadata(mgr, "node-a", "1.1.1.1")
			sendHostMetadata(mgr, "node-b", "1.1.1.2")
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(HaveLen(1))
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove entry when hash changes after adding a third node", func() {
			// Adding node-c changes the hash: "10.0.0.100" now selects node-c, not node-b.
			sendHostMetadata(mgr, "node-c", "1.1.1.3")
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("node removed causes re-evaluation", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// With 3 nodes, "10.0.0.100" -> node-c. We are node-b (not selected).
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-b")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(BeEmpty())
		})

		AfterEach(func() { mgr.cancel() })

		It("should add entry when hash changes after removing node-c", func() {
			// Removing node-c leaves ["node-a","node-b"]: "10.0.0.100" -> node-b (idx 1).
			sendHostMetadataRemove(mgr, "node-c")
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("non-LoadBalancer service type ignored", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "ClusterIP", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("LB IP outside host subnet", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "192.168.1.100" hashes to node-a with 3 nodes.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "192.168.1.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("multiple LB services", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" -> node-c, "10.0.0.101" -> node-a. We are node-c.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("svc-1", "default", "LoadBalancer", "10.0.0.100"))
			mgr.OnUpdate(svcUpdate("svc-2", "default", "LoadBalancer", "10.0.0.101"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should only add entry for the IP this node is selected for", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(1))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("deprecated loadbalancer_ip field", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			// Use the deprecated LoadbalancerIp field instead of LoadbalancerIngressIps.
			mgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "my-svc",
				Namespace:      "default",
				Type:           "LoadBalancer",
				LoadbalancerIp: "10.0.0.100",
			})
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should still add a proxy ARP entry", func() {
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("pod IPs and LB IPs coexist", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should have entries for both pod IP and LB IP", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(2))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("selectNodeForIP", func() {
		It("should be deterministic", func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)

			result1 := mgr.selectNodeForIP("10.0.0.100")
			result2 := mgr.selectNodeForIP("10.0.0.100")
			Expect(result1).To(Equal(result2))
			Expect(result1).To(BeTrue()) // node-c is selected for this IP
			mgr.cancel()
		})

		It("should return false with zero nodes", func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			Expect(mgr.selectNodeForIP("10.0.0.100")).To(BeFalse())
			mgr.cancel()
		})
	})

	Describe("no duplicate GARP on re-reconciliation for LB IP", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())

			Eventually(func() int {
				return len(garpSender.getCalls())
			}).Should(Equal(1))

			garpSender.reset()
			mgr.dirty = true
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not send duplicate GARP", func() {
			Consistently(func() int {
				return len(garpSender.getCalls())
			}).Should(Equal(0))
		})
	})

	Describe("IPv6 LB IP filtered in IPv4 manager", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "fd00::100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add any proxy ARP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("service type changed from LoadBalancer to ClusterIP", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getEntries()).To(HaveLen(1))

			// Service type changed to ClusterIP.
			mgr.OnUpdate(svcUpdate("my-svc", "default", "ClusterIP", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove the proxy ARP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})
})

var _ = Describe("Proxy ARP manager - LB VIP dummy routes", func() {
	var (
		mgr        *proxyARPManager
		nl         *mockNetlinkForProxyARP
		garpSender *mockGARPSender
	)

	setupThreeNodes := func(mgr *proxyARPManager) {
		sendHostMetadata(mgr, "node-a", "1.1.1.1")
		sendHostMetadata(mgr, "node-b", "1.1.1.2")
		sendHostMetadata(mgr, "node-c", "1.1.1.3")
	}

	Describe("route added for LB IP on selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" hashes to node-c with 3 nodes.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should create the dummy interface and add a /32 route", func() {
			_, err := nl.LinkByName(proxyARPDummyIface)
			Expect(err).ToNot(HaveOccurred())
			routeIPs := nl.getRouteIPs()
			Expect(routeIPs.Contains("10.0.0.100")).To(BeTrue())
		})

		It("should have both proxy entry and route", func() {
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())
		})
	})

	Describe("no route added for non-selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" hashes to node-c, we are node-a.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add any routes", func() {
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("no route added for pod IPs", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManager(nl, garpSender)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should have the proxy entry but no dummy routes", func() {
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("route removed when service deleted", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())

			mgr.OnUpdate(svcRemove("my-svc", "default"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove the route and the proxy entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("route removed when service type changes to ClusterIP", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())

			mgr.OnUpdate(svcUpdate("my-svc", "default", "ClusterIP", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove the route", func() {
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("route removed when node selection changes", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// With 2 nodes ["node-a","node-b"], "10.0.0.100" -> node-b (idx 1).
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-b")
			sendHostMetadata(mgr, "node-a", "1.1.1.1")
			sendHostMetadata(mgr, "node-b", "1.1.1.2")
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())

			// Adding node-c changes hash: "10.0.0.100" -> node-c, not node-b.
			sendHostMetadata(mgr, "node-c", "1.1.1.3")
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should remove both the route and the proxy entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("multiple LB services with routes", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "10.0.0.100" -> node-c, "10.0.0.101" -> node-a. We are node-c.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("svc-1", "default", "LoadBalancer", "10.0.0.100"))
			mgr.OnUpdate(svcUpdate("svc-2", "default", "LoadBalancer", "10.0.0.101"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should only add a route for the selected LB IP", func() {
			routeIPs := nl.getRouteIPs()
			Expect(routeIPs.Contains("10.0.0.100")).To(BeTrue())
			Expect(routeIPs.Contains("10.0.0.101")).To(BeFalse())
		})

		Context("after removing the selected service", func() {
			BeforeEach(func() {
				mgr.OnUpdate(svcRemove("svc-1", "default"))
				Expect(mgr.CompleteDeferredWork()).To(Succeed())
			})

			It("should remove the route", func() {
				Expect(nl.getRoutes()).To(BeEmpty())
			})
		})
	})

	Describe("LB route resync after external flush", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())

			// Simulate external flush of routes.
			nl.flushRoutes()
			Expect(nl.getRoutes()).To(BeEmpty())

			// Trigger resync.
			mgr.QueueResync()
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should re-create the LB route", func() {
			Expect(nl.getRouteIPs().Contains("10.0.0.100")).To(BeTrue())
		})

		It("should re-create the proxy entry", func() {
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})
	})

	Describe("LB IP outside host subnet gets no route", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			// "192.168.1.100" hashes to node-a with 3 nodes.
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "192.168.1.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not add any routes (IP not in any host subnet)", func() {
			Expect(nl.getRoutes()).To(BeEmpty())
		})
	})

	Describe("coexisting pod IPs and LB IPs - only LB gets route", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyARP()
			garpSender = newMockGARPSender()
			mgr = newTestProxyARPManagerWithHostname(nl, garpSender, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should have proxy entries for both IPs", func() {
			Expect(nl.getEntries()).To(HaveLen(2))
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.50"}))
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "10.0.0.100"}))
		})

		It("should only have a dummy route for the LB IP, not the pod IP", func() {
			routeIPs := nl.getRouteIPs()
			Expect(routeIPs.Contains("10.0.0.100")).To(BeTrue())
			Expect(routeIPs.Contains("10.0.0.50")).To(BeFalse())
		})
	})
})

func newTestProxyNDPManager(nl *mockNetlinkForProxyARP, unaSender *mockGARPSender, procSys procSysWriter) *proxyARPManager {
	config := Config{
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	return newProxyARPManagerWithShims(config, 6, nl, unaSender.send, procSys)
}

// Helper to create a WorkloadEndpointUpdate with IPv6 nets.
func wepUpdateV6(orchID, wlID, epID string, ipv6Nets ...string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Ipv6Nets: ipv6Nets,
		},
	}
}

var _ = Describe("Proxy NDP manager (IPv6)", func() {
	var (
		mgr        *proxyARPManager
		nl         *mockNetlinkForProxyARP
		unaSender  *mockGARPSender
		procSysLog map[string]string
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyARP()
		unaSender = newMockGARPSender()
		procSysLog = make(map[string]string)
		mgr = newTestProxyNDPManager(nl, unaSender, func(path, value string) error {
			procSysLog[path] = value
			return nil
		})
	})

	AfterEach(func() {
		mgr.cancel()
	})

	Describe("basic IPv6 proxy NDP entry", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "fd00::1/64")
			sendIfaceCIDRUpdate(mgr, "eth0", "fd00::1/128")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add a proxy NDP entry for the pod IPv6 on eth0", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "fd00::50"}))
		})

		It("should send unsolicited NA", func() {
			Eventually(func() []garpCall {
				return unaSender.getCalls()
			}).Should(ContainElement(garpCall{ifaceName: "eth0", podIP: "fd00::50"}))
		})

		It("should enable proxy_ndp on eth0", func() {
			Expect(procSysLog).To(HaveKeyWithValue("/proc/sys/net/ipv6/conf/eth0/proxy_ndp", "1"))
		})
	})

	Describe("IPv6 workload removed", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "fd00::1/64")
			sendIfaceCIDRUpdate(mgr, "eth0", "fd00::1/128")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))

			mgr.OnUpdate(wepRemove("k8s", "default/pod1", "eth0"))
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should remove the proxy NDP entry", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("IPv4 addresses filtered in IPv6 manager", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth0", "10.0.0.1/32")
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add any proxy NDP entries", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})
	})

	Describe("proxy_ndp not set again on second reconcile", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "fd00::1/64")
			sendIfaceCIDRUpdate(mgr, "eth0", "fd00::1/128")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(procSysLog).To(HaveKeyWithValue("/proc/sys/net/ipv6/conf/eth0/proxy_ndp", "1"))

			// Clear the log and add another pod to trigger a second reconcile.
			procSysLog = make(map[string]string)
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod2", "eth0", "fd00::51/128"))
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not write proxy_ndp again", func() {
			Expect(procSysLog).To(BeEmpty())
		})
	})

	Describe("multiple IPv6 pods same interface", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "fd00::1/64")
			sendIfaceCIDRUpdate(mgr, "eth0", "fd00::1/128")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod2", "eth0", "fd00::51/128"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add proxy NDP entries for both pods", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(2))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "fd00::50"}))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "fd00::51"}))
		})
	})

})

var _ = Describe("Proxy ARP manager - resync with kernel", func() {
	var (
		mgr  *proxyARPManager
		nl   *mockNetlinkForProxyARP
		garp *mockGARPSender
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyARP()
		garp = newMockGARPSender()
		mgr = newTestProxyARPManager(nl, garp)

		// Set up a host interface with 192.168.1.0/24 on eth0.
		nl.setIfaceAddr("eth0", "192.168.1.1/24")
		sendIfaceCIDRUpdate(mgr, "eth0", "192.168.1.1/32")
	})

	Describe("flushed entries are re-created", func() {
		BeforeEach(func() {
			// Program a pod IP.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))

			// Wait for async GARP worker to drain, then reset tracker.
			Eventually(garp.getCalls).Should(HaveLen(1))
			garp.reset()

			// Simulate external flush of all proxy ARP entries.
			nl.flushEntries()
			Expect(nl.getEntries()).To(BeEmpty())

			// Trigger resync.
			mgr.QueueResync()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should re-create the flushed entry", func() {
			Expect(nl.getEntries()).To(HaveLen(1))
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
		})

		It("should send GARP for the re-created entry", func() {
			Eventually(garp.getCalls).Should(HaveLen(1))
			Expect(garp.getCalls()[0]).To(Equal(garpCall{ifaceName: "eth0", podIP: "192.168.1.50"}))
		})
	})

	Describe("stale kernel entries are removed", func() {
		BeforeEach(func() {
			// Program a pod IP.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// Inject a stale entry that shouldn't be there.
			nl.injectEntry("eth0", "192.168.1.99")

			// Trigger resync.
			mgr.QueueResync()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should remove the stale entry and keep the valid one", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(1))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
			Expect(entries).NotTo(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.99"}))
		})
	})

	Describe("no-op when kernel matches desired", func() {
		BeforeEach(func() {
			// Program entries.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))

			// Wait for async GARP worker to drain, then reset tracker.
			Eventually(garp.getCalls).Should(HaveLen(1))
			garp.reset()

			// Resync without any external changes.
			mgr.QueueResync()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not send any GARP", func() {
			Consistently(garp.getCalls).Should(BeEmpty())
		})

		It("should still have the same entries", func() {
			Expect(nl.getEntries()).To(HaveLen(1))
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
		})
	})

	Describe("resync on subset of interfaces", func() {
		BeforeEach(func() {
			// Set up two interfaces.
			nl.setIfaceAddr("eth1", "10.0.0.1/24")
			sendIfaceCIDRUpdate(mgr, "eth1", "10.0.0.1/32")

			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			mgr.OnUpdate(wepUpdate("k8s", "default/pod2", "eth0", "10.0.0.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(2))

			// Wait for async GARP worker to drain, then reset tracker.
			Eventually(garp.getCalls).Should(HaveLen(2))
			garp.reset()

			// Flush only eth0 entries (simulate partial kernel flush).
			nl.mu.Lock()
			for entry := range nl.proxyNeighs {
				if entry.ifaceName == "eth0" {
					delete(nl.proxyNeighs, entry)
				}
			}
			nl.mu.Unlock()

			// Trigger resync.
			mgr.QueueResync()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should re-create only the flushed eth0 entry", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(2))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth1", podIP: "10.0.0.50"}))
		})

		It("should send GARP only for the re-created entry", func() {
			Eventually(garp.getCalls).Should(HaveLen(1))
			Expect(garp.getCalls()[0]).To(Equal(garpCall{ifaceName: "eth0", podIP: "192.168.1.50"}))
		})
	})

	Describe("QueueResync without dirty triggers reconciliation", func() {
		BeforeEach(func() {
			// Program entries and complete initial work.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// Wait for async GARP worker to drain, then reset tracker.
			Eventually(garp.getCalls).Should(HaveLen(1))

			// Flush kernel entries.
			nl.flushEntries()

			// Call CompleteDeferredWork without QueueResync — dirty is false.
			garp.reset()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should NOT re-create entries without QueueResync", func() {
			Expect(nl.getEntries()).To(BeEmpty())
		})

		It("should re-create entries after QueueResync", func() {
			mgr.QueueResync()
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(nl.getEntries()).To(HaveLen(1))
			Expect(nl.getEntries()).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
		})
	})

	Describe("resync with LB IPs and pod IPs coexisting", func() {
		BeforeEach(func() {
			// Set up cluster nodes so hash-based selection works.
			sendHostMetadata(mgr, "test-node", "192.168.1.1")

			// Program a pod IP and a LB IP.
			mgr.OnUpdate(wepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			mgr.OnUpdate(svcUpdate("default", "my-svc", "LoadBalancer", "192.168.1.100"))
			err := mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// With only one node, all LB IPs are selected for this node.
			Expect(nl.getEntries()).To(HaveLen(2))

			// Wait for async GARP worker to drain, then reset tracker.
			Eventually(func() int { return len(garp.getCalls()) }).Should(Equal(2))
			garp.reset()

			// Flush all kernel entries.
			nl.flushEntries()
			Expect(nl.getEntries()).To(BeEmpty())

			// Trigger resync.
			mgr.QueueResync()
			err = mgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should re-create both pod and LB entries", func() {
			entries := nl.getEntries()
			Expect(entries).To(HaveLen(2))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.50"}))
			Expect(entries).To(HaveKey(proxyARPEntry{ifaceName: "eth0", podIP: "192.168.1.100"}))
		})

		It("should send GARP for both re-created entries", func() {
			Eventually(func() int { return len(garp.getCalls()) }).Should(Equal(2))
		})
	})
})
