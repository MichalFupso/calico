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

func (m *mockNetlinkForProxyARP) getEntries() map[proxyARPEntry]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[proxyARPEntry]bool)
	for k, v := range m.proxyNeighs {
		result[k] = v
	}
	return result
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
	config := Config{
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	return newProxyARPManagerWithShims(config, 4, nl, garpSender.send)
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

func newTestProxyNDPManager(nl *mockNetlinkForProxyARP, unaSender *mockGARPSender) *proxyARPManager {
	config := Config{
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	return newProxyARPManagerWithShims(config, 6, nl, unaSender.send)
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
		mgr       *proxyARPManager
		nl        *mockNetlinkForProxyARP
		unaSender *mockGARPSender
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyARP()
		unaSender = newMockGARPSender()
		mgr = newTestProxyNDPManager(nl, unaSender)
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
