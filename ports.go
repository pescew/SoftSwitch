package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/xlab/treeprint"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
)

const MAX_IFACES = 80
const TRAFFIC_KEY_SIZE = 16
const STATS_ENABLED = false

var FEATURES_ENABLE = map[string]bool{
	// "rx-gro":                  true,
	"rx-vlan-hw-parse":  true,
	"tx-vlan-hw-insert": true,
	// "rx-hashing":              true,
	// "tx-tcp-segmentation":     true,
	// "tx-tcp-ecn-segmentation": true,
	// "tx-tcp6-segmentation":    true,
	// "generic-receive-offload": true,
}
var FEATURES_DISABLE = map[string]bool{
	// "rx-gro":                  false,
	"rx-vlan-hw-parse":  false,
	"tx-vlan-hw-insert": false,
	// "rx-hashing":              false,
	// "tx-tcp-segmentation":     false,
	// "tx-tcp-ecn-segmentation": false,
	// "tx-tcp6-segmentation":    false,
	// "generic-receive-offload": false,
}

type BridgeGroup struct {
	ifMap        map[string]*switchPort
	ifMapByIndex map[uint16]*switchPort

	ifList []*switchPort
}

type portSettings struct {
	// Tap              bool     `json:"tap,omitempty" yaml:"tap,omitempty"` //todo
	PVID             uint16   `json:"pvid,omitempty" yaml:"pvid,omitempty"`
	Vlans            []uint16 `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	Trunk            bool     `json:"trunk,omitempty" yaml:"trunk,omitempty"`
	XDPMode          string   `json:"xdpMode,omitempty" yaml:"xdpMode,omitempty"`
	Transparent      bool     `json:"transparent,omitempty" yaml:"transparent,omitempty"`
	HookDrop         string   `json:"hookDrop,omitempty" yaml:"hookDrop,omitempty"`
	HookEgress       string   `json:"hookEgress,omitempty" yaml:"hookEgress,omitempty"`
	ingressFiltering bool     `json:"-" yaml:"-"`
}

func (settings *portSettings) Validate() {
	if settings.Trunk {
		settings.Vlans = []uint16{}
	} else {
		allKeys := make(map[uint16]bool)
		list := []uint16{}
		for _, vlan := range settings.Vlans {
			if vlan != settings.PVID {
				_, exists := allKeys[vlan]
				if !exists {
					allKeys[vlan] = true
					list = append(list, vlan)
				}
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i] < list[j] //todo- vlan priority sort order, for now numerical order
		})
		settings.Vlans = list
	}
}

func DownAll() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		err = DownInterface(iface.Name)
		if err != nil {
			return err
		}
	}

	/////// Close FDB Map
	mapFdb, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_fdb_xdp", nil)
	if err == nil {
		if mapFdb.IsPinned() {
			err = mapFdb.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapFdb.Close()
		if err != nil {
			return err
		}
	}

	/////// Close xdp stats
	mapStats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_stats_xdp", nil)
	if err == nil {
		if mapStats.IsPinned() {
			err = mapStats.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapStats.Close()
		if err != nil {
			return err
		}
	}

	/////// Close Jump Map xdp
	mapJmpXdp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_xdp", nil)
	if err == nil {
		if mapJmpXdp.IsPinned() {
			err = mapJmpXdp.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpXdp.Close()
		if err != nil {
			return err
		}
	}

	/////// Close Jump Map tc
	mapJmpTc, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_tc", nil)
	if err == nil {
		if mapJmpTc.IsPinned() {
			err = mapJmpTc.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpTc.Close()
		if err != nil {
			return err
		}
	}

	fmt.Printf("%s down\n", PROG_NAME)
	return nil
}

func DownInterface(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer ethHandle.Close()

	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}

	filtersIngress, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}

	/////// TC detach
	matchedIngress := false
	for _, filt := range filtersIngress {
		attrs := filt.Attrs()
		if filt.Type() == "bpf" && attrs.Protocol == unix.ETH_P_ALL && attrs.Handle == netlink.MakeHandle(0, 1) {
			matchedIngress = true

			fmt.Printf("[%s] Setting port down... ", iface.Name)
			/////// set port down
			err = netlink.LinkSetDown(link)
			if err != nil {
				return err
			}

			err = netlink.SetPromiscOff(link)
			if err != nil {
				return err
			}

			ethHandle.Change(iface.Name, FEATURES_ENABLE)

			fmt.Printf("detaching TC... ")
			/////// TC detach
			err = netlink.FilterDel(filt)
			if err != nil {
				return err
			}
		}
	}

	/////// TC EGRESS detach
	filtersEgress, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	for _, filt := range filtersEgress {
		attrs := filt.Attrs()
		if matchedIngress && filt.Type() == "bpf" && attrs.Protocol == unix.ETH_P_ALL && attrs.Handle == netlink.MakeHandle(0, 1) {
			err = netlink.FilterDel(filt)
			if err != nil {
				return err
			}
		}
	}

	/////// XDP detach
	if matchedIngress {
		fmt.Printf("detaching XDP... ")
		// err = netlink.LinkSetXdpFd(link, -1)
		err = netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkDriver)))
		if err != nil {
			return err
		}

		err = netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeGeneric)))
		if err != nil {
			return err
		}

		// todo: delete if tap device
		// if strings.HasPrefix(iface.Name, TAP_DEV_PREFIX) {
		// 	businfo, err := ethHandle.BusInfo(iface.Name)
		// 	if err == nil {
		// 		if businfo == "tap" {
		// 			err = netlink.LinkDel(link)
		// 			if err != nil {
		// 				return err
		// 			}
		// 		}
		// 	}
		// }

		fmt.Printf("👌\n")
	}

	return nil
}

func (bridge *BridgeGroup) Down() error {
	for _, port := range bridge.ifList {
		err := DownInterface(port.iface.Name)
		if err != nil {
			return err
		}
	}

	/////// Close FDB Map
	mapFdb, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_fdb_xdp", nil)
	if err == nil {
		if mapFdb.IsPinned() {
			err = mapFdb.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapFdb.Close()
		if err != nil {
			return err
		}
	}

	/////// Close xdp stats
	mapStats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_stats_xdp", nil)
	if err == nil {
		if mapStats.IsPinned() {
			err = mapStats.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapStats.Close()
		if err != nil {
			return err
		}
	}

	/////// Close xdp Jump Map
	mapJmpXdp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_xdp", nil)
	if err == nil {
		if mapJmpXdp.IsPinned() {
			err = mapJmpXdp.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpXdp.Close()
		if err != nil {
			return err
		}
	}

	/////// Close tc Jump Map
	mapJmpTc, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_tc", nil)
	if err == nil {
		if mapJmpTc.IsPinned() {
			err = mapJmpTc.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpTc.Close()
		if err != nil {
			return err
		}
	}

	fmt.Printf("%s down\n", PROG_NAME)
	return nil
}

func (group *BridgeGroup) GetPortByName(name string) (*switchPort, error) {
	port, exists := group.ifMap[name]
	if !exists {
		return nil, fmt.Errorf("Port doesn't exist in bridge (name: %s)", name)
	}
	return port, nil
}

func (group *BridgeGroup) GetPortByIndex(index int) (*switchPort, error) {
	port, exists := group.ifMapByIndex[uint16(index)]
	if !exists {
		return nil, fmt.Errorf("Port doesn't exist in bridge (index: %d)", index)
	}
	return port, nil
}

func (group *BridgeGroup) GetPortList() []*switchPort {
	return group.ifList
}

func (group *BridgeGroup) buildPortList() []*switchPort {
	list := maps.Values(group.ifMap)
	sort.Slice(list, func(i, j int) bool {
		return list[i].iface.Index < list[j].iface.Index
	})

	return list
}

func (group *BridgeGroup) prettyPrint() string {
	tree := treeprint.NewWithRoot(PROG_NAME)

	for _, port := range group.GetPortList() {
		mode := port.settings.XDPMode
		if mode == "" {
			mode = DEFAULT_XDP_MODE
		}

		treePortName := tree.AddBranch(fmt.Sprintf("%s", port.iface.Name))
		treePortName.AddNode(fmt.Sprintf("driver: %s (%s)", port.driverName, mode))
		if port.settings.Transparent {
			treePortName.AddNode("transparent: true")
		}

		treePortVlans := treePortName.AddBranch("VLANs")
		treePortVlans.AddNode(fmt.Sprintf("untagged: %d", port.settings.PVID))

		if port.settings.Trunk {
			treePortVlans.AddNode("tagged: trunk")
		} else if len(port.settings.Vlans) > 0 {
			switch len(port.settings.Vlans) {
			case 0:
				_ = 0
			case 1:
				treePortVlans.AddNode(fmt.Sprintf("tagged: %d", port.settings.Vlans[0]))
			default:
				treePortTagged := treePortVlans.AddBranch("tagged:")
				for _, vlan := range port.settings.Vlans {
					treePortTagged.AddNode(fmt.Sprintf("%d", vlan))
				}
			}
		}

	}

	return tree.String()
}

func (bridge *BridgeGroup) getStats() []portStats {
	var list []portStats
	for _, port := range bridge.ifList {
		list = append(list, port.Stats)
	}
	return list
}

func ip2int(ip net.IP) uint32 {
	// if len(ip) == 16 {
	// 	panic("no sane way to convert ipv6 into uint32")
	// }
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func int2netip(nn uint32) (addr netip.Addr, ok bool) {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, nn)
	addr, ok = netip.AddrFromSlice(ipBytes)
	return
}

type IPRecord struct {
	IP        string       `json:"ip" yaml:"ip" maxminddb:"ip"`
	RDNS      string       `json:"rdns" yaml:"rdns" maxminddb:"rdns"`
	Continent string       `json:"continent" yaml:"continent" maxminddb:"continent"`
	Country   string       `json:"country" yaml:"country" maxminddb:"country"`
	City      string       `json:"city" yaml:"city" maxminddb:"city"`
	Lat       float32      `json:"lat" yaml:"lat" maxminddb:"lat"`
	Lng       float32      `json:"lng" yaml:"lng" maxminddb:"lng"`
	Traffic   StatsTraffic `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	PrevHop   *IPRecord    `json:"prevHop,omitempty" yaml:"prevHop,omitempty"`
}

func (port *switchPort) refreshStats(countLocal, traceroute bool) {

	iter := port.eBPF.internals.MapStatsTraffic.Iterate()
	var keyBytes [TRAFFIC_KEY_SIZE]byte
	seen := make(map[[TRAFFIC_KEY_SIZE]byte]struct{})
	cpuVals := make([][]byte, runtime.NumCPU())
	trafficTotalPort := NewStatsTraffic()
	for iter.Next(&keyBytes, &cpuVals) { // grab array of per-cpu stats for this key on this port
		_, exists := seen[keyBytes]
		if exists {
			continue // skip if already seen
		}
		seen[keyBytes] = struct{}{}

		key := StatsTrafficKey{
			SrcIPv4:       binary.BigEndian.Uint32(keyBytes[:4]),
			DstIPv4:       binary.BigEndian.Uint32(keyBytes[4:8]),
			Vlan:          binary.LittleEndian.Uint16(keyBytes[8:10]),
			ProtoL2:       binary.LittleEndian.Uint16(keyBytes[10:12]),
			ProtoL3:       binary.LittleEndian.Uint16(keyBytes[12:14]),
			TargetIfIndex: binary.LittleEndian.Uint16(keyBytes[14:16]),
		}

		srcIp := int2ip(key.SrcIPv4)
		dstIp := int2ip(key.DstIPv4)

		if srcIp.IsUnspecified() || dstIp.IsUnspecified() {
			continue
		}

		if !countLocal && srcIp.IsPrivate() {
			continue
		}
		trafficTotalKey := NewStatsTraffic()

		newTrafficOnKey := false
		for cpuIdx, cpuValBytes := range cpuVals { // iterate array of per-cpu stats for this key on this port
			timestamp := binary.LittleEndian.Uint64(cpuValBytes[:8])
			if timestamp == 0 {
				continue
			}

			cpuTraffic := UnmarshallStatsTraffic(cpuValBytes)
			trafficTotalKey.Add(cpuTraffic)

			prevByCore, prevByCoreExists := port.Traffic.trafficByCore.Peek(cpuIdx)
			if !prevByCoreExists || timestamp > prevByCore.LatestPacket.Timestamp {
				port.Traffic.trafficByCore.Add(cpuIdx, cpuTraffic)
				newTrafficOnKey = true
			}

		}
		trafficTotalPort.Add(trafficTotalKey)

		if newTrafficOnKey {
			var trafficDiff StatsTraffic
			prev, exists, _ := port.Traffic.trafficByKey.PeekOrAdd(key, trafficTotalKey)
			if !exists {
				prev = NewStatsTraffic()
				trafficDiff = trafficTotalKey
			} else {
				port.Traffic.trafficByKey.Add(key, trafficTotalKey)
				trafficDiff = trafficTotalKey.Sub(prev)
			}

			if key.TargetIfIndex != uint16(port.iface.Index) {

				prev, exists, _ = port.Traffic.trafficByDstIface.PeekOrAdd(key.TargetIfIndex, trafficDiff)
				if exists {
					prev.Add(trafficDiff)
					port.Traffic.trafficByDstIface.Add(key.TargetIfIndex, prev)
				}
			}

			prev, exists, _ = port.Traffic.trafficBySrcIPv4.PeekOrAdd(key.SrcIPv4, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficBySrcIPv4.Add(key.SrcIPv4, prev) //todo - remove this and add mutex to StatsTraffic?
			}

			prev, exists, _ = port.Traffic.trafficByDstIPv4.PeekOrAdd(key.DstIPv4, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByDstIPv4.Add(key.DstIPv4, prev)
			}

			prev, exists, _ = port.Traffic.trafficByVLAN.PeekOrAdd(key.Vlan, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByVLAN.Add(key.Vlan, prev)
			}

			prev, exists, _ = port.Traffic.trafficByProtoL2.PeekOrAdd(key.ProtoL2, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByProtoL2.Add(key.ProtoL2, prev)
			}

			prev, exists, _ = port.Traffic.trafficByProtoL3.PeekOrAdd(key.ProtoL3, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByProtoL3.Add(key.ProtoL3, prev)
			}
		}
	}

	port.Traffic.mutex.Lock()
	port.Traffic.trafficTotal = trafficTotalPort
	port.Traffic.mutex.Unlock()
	return
}

func (bridge *BridgeGroup) refreshStats() {
	var wg sync.WaitGroup
	for _, port := range bridge.ifList {
		wg.Add(1)
		go func(port *switchPort) {
			defer wg.Done()

			portTraffic := new(StatsTraffic)
			portTraffic.LatestPacket.Timestamp = 1

			iter := port.eBPF.internals.MapStatsTraffic.Iterate()

			var keyBytes [TRAFFIC_KEY_SIZE]byte

			seen := make(map[[TRAFFIC_KEY_SIZE]byte]struct{})

			cpuVals := make([][]byte, runtime.NumCPU())

			for iter.Next(&keyBytes, &cpuVals) { //cpus array

				_, exists := seen[keyBytes]
				if exists {
					continue
				}
				seen[keyBytes] = struct{}{}

				key := StatsTrafficKey{
					SrcIPv4:       binary.BigEndian.Uint32(keyBytes[:4]),
					DstIPv4:       binary.BigEndian.Uint32(keyBytes[4:8]),
					Vlan:          binary.LittleEndian.Uint16(keyBytes[8:10]),
					ProtoL2:       binary.LittleEndian.Uint16(keyBytes[10:12]),
					ProtoL3:       binary.LittleEndian.Uint16(keyBytes[12:14]),
					TargetIfIndex: binary.LittleEndian.Uint16(keyBytes[14:16]),
				}
				srcIP := int2ip(key.SrcIPv4)
				fmt.Println(srcIP.String(), key.Vlan)

				for cpuIdx, cpuValBytes := range cpuVals { //per cpu val
					_ = cpuIdx

					Timestamp := binary.LittleEndian.Uint64(cpuValBytes[:8])
					if Timestamp > portTraffic.LatestPacket.Timestamp {
						portTraffic = &StatsTraffic{
							mutex: sync.RWMutex{},
							LatestPacket: LatestPacketInfo{
								Timestamp: Timestamp,
								Tagged:    cpuValBytes[8],
								Size:      binary.BigEndian.Uint16(cpuValBytes[9:11]),
							},

							RxDroppedBytes:      binary.LittleEndian.Uint64(cpuValBytes[11:19]),
							RxDroppedPackets:    binary.LittleEndian.Uint64(cpuValBytes[19:27]),
							RxPassedBytes:       binary.LittleEndian.Uint64(cpuValBytes[27:35]),
							RxPassedPackets:     binary.LittleEndian.Uint64(cpuValBytes[35:43]),
							RxRedirectedBytes:   binary.LittleEndian.Uint64(cpuValBytes[43:51]),
							RxRedirectedPackets: binary.LittleEndian.Uint64(cpuValBytes[51:59]),
						}
					}
				}

			}

		}(port)
	}

	wg.Wait()
	return
}

func (bridge *BridgeGroup) updateStats() error {
	for _, port := range bridge.ifList {
		stats := make([]StatsXDP, MAX_IFACES)
		tsStart := time.Now()
		err := port.eBPF.internals.MapStatsXDP.Lookup(uint32(port.iface.Index), &stats)
		if err != nil {
			return err
		}
		ttlStats := StatsXDP{}
		for _, coreStats := range stats {
			ttlStats.RxDroppedBytes += coreStats.RxDroppedBytes
			ttlStats.RxDroppedPackets += coreStats.RxDroppedPackets
			ttlStats.RxPassedBytes += coreStats.RxPassedBytes
			ttlStats.RxPassedPackets += coreStats.RxPassedPackets
			ttlStats.RxRedirectedBytes += coreStats.RxRedirectedBytes
			ttlStats.RxRedirectedPackets += coreStats.RxRedirectedPackets
			if coreStats.RxLastTimestamp > ttlStats.RxLastTimestamp {
				ttlStats.RxLastTimestamp = coreStats.RxLastTimestamp
			}

			ttlStats.TxRedirectedBytes += coreStats.TxRedirectedBytes
			ttlStats.TxRedirectedPackets += coreStats.TxRedirectedPackets
			if coreStats.TxLastTimestamp > ttlStats.TxLastTimestamp {
				ttlStats.TxLastTimestamp = coreStats.TxLastTimestamp
			}
		}
		port.Stats.mutex.Lock()
		port.Stats.RxPackets = ttlStats.RxPassedPackets + ttlStats.RxDroppedPackets + ttlStats.RxRedirectedPackets
		port.Stats.RxBytes = ttlStats.RxPassedBytes + ttlStats.RxDroppedBytes + ttlStats.RxRedirectedBytes
		port.Stats.TxPackets = ttlStats.TxRedirectedPackets
		port.Stats.TxBytes = ttlStats.TxRedirectedBytes
		var diffRxBytes, diffTxBytes uint64
		if port.Stats.RxBytes == 0 {
			diffRxBytes = port.Stats.XdpStats.RxPassedBytes + port.Stats.XdpStats.RxDroppedBytes + port.Stats.XdpStats.RxRedirectedBytes
		} else {
			diffRxBytes = port.Stats.RxBytes - (port.Stats.XdpStats.RxPassedBytes + port.Stats.XdpStats.RxDroppedBytes + port.Stats.XdpStats.RxRedirectedBytes)
		}
		if port.Stats.TxBytes == 0 {
			diffTxBytes = port.Stats.XdpStats.TxRedirectedBytes
		} else {
			diffTxBytes = port.Stats.TxBytes - port.Stats.XdpStats.TxRedirectedBytes
		}
		diffNanoSecs := tsStart.UnixNano() - port.Stats.UpdatedAt.UnixNano()
		port.Stats.UpdatedAt = tsStart
		mult := 1000000000 / float64(diffNanoSecs)
		port.Stats.RxRate = uint64(float64(diffRxBytes) * mult)
		port.Stats.TxRate = uint64(float64(diffTxBytes) * mult)
		port.Stats.XdpStatsPerCore = stats
		port.Stats.XdpStats = ttlStats
		port.Stats.xdpStatsHistory.PushBack(port.Stats.XdpStats)
		if port.Stats.xdpStatsHistory.Len() >= 100000 {
			_ = port.Stats.xdpStatsHistory.Remove(port.Stats.xdpStatsHistory.Front())
		}
		port.Stats.mutex.Unlock()
	}
	return nil
}

func (group *BridgeGroup) addPort(ifName string, settings portSettings) error {
	var err error
	name := ifName

	//todo - tun/tap device
	// var waterInterface *water.Interface = nil
	// if settings.Tap {
	// 	if !strings.HasPrefix(name, TAP_DEV_PREFIX) {
	// 		name = TAP_DEV_PREFIX + name
	// 	}
	// 	waterConfig := water.Config{
	// 		DeviceType: water.TAP,
	// 		PlatformSpecificParams: water.PlatformSpecificParams{
	// 			Name:        name,
	// 			Persist:     true,
	// 			Permissions: nil,
	// 			MultiQueue:  true,
	// 		},
	// 	}
	// 	waterInterface, err = water.New(waterConfig)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	name = waterInterface.Name()
	// }

	ifReference, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}

	nl, err := netlink.LinkByName(ifReference.Name)
	if err != nil {
		return err
	}

	driverName, err := ethHandle.DriverName(ifReference.Name)
	if err != nil {
		return err
	}

	trafficByCore, err := lru.New[int, StatsTraffic](runtime.NumCPU())
	if err != nil {
		return err
	}

	trafficByKey, err := lru.New[StatsTrafficKey, StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficBySrcIPv4, err := lru.New[uint32, StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficByDstIPv4, err := lru.New[uint32, StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficByVLAN, err := lru.New[uint16, StatsTraffic](4094)
	if err != nil {
		return err
	}

	trafficByProtoL2, err := lru.New[uint16, StatsTraffic](256)
	if err != nil {
		return err
	}

	trafficByProtoL3, err := lru.New[uint16, StatsTraffic](256)
	if err != nil {
		return err
	}

	trafficByDstIface, err := lru.New[uint16, StatsTraffic](MAX_IFACES)
	if err != nil {
		return err
	}

	port := switchPort{
		iface:         ifReference,
		settings:      settings,
		driverName:    driverName,
		speed:         0,
		ethtoolHandle: ethHandle,
		ethtoolCmd:    &ethtool.EthtoolCmd{},
		netlink:       nl,
		// Tap:           waterInterface, //todo
		Stats: portStats{},
		Traffic: TrafficObserver{ //todo -move to port
			mutex:             sync.RWMutex{},
			trafficTotal:      NewStatsTraffic(),
			trafficByCore:     trafficByCore,
			trafficByKey:      trafficByKey,
			trafficBySrcIPv4:  trafficBySrcIPv4,
			trafficByDstIPv4:  trafficByDstIPv4,
			trafficByVLAN:     trafficByVLAN,
			trafficByProtoL2:  trafficByProtoL2,
			trafficByProtoL3:  trafficByProtoL3,
			trafficByDstIface: trafficByDstIface,
		},
	}
	port.Stats.PortName = ifReference.Name

	group.ifMap[ifName] = &port
	group.ifMapByIndex[uint16(ifReference.Index)] = &port

	return nil
}

func (bridge *BridgeGroup) Up() error {
	return bridge.allUpEbpf()
}

func (bridge *BridgeGroup) allUpEbpf() error {
	for _, port := range bridge.ifList {
		err := port.upEbpf(bridge.ifList)
		if err != nil {
			return err
		}
	}
	return nil
}

func (group *BridgeGroup) allDownEbpf() {
	for _, port := range group.ifMap {
		err := port.downEbpf()
		if err != nil {
			fmt.Println("ERROR: " + err.Error())
		}
	}
}

type TrafficObserver struct {
	mutex             sync.RWMutex
	trafficTotal      StatsTraffic
	trafficByCore     *lru.Cache[int, StatsTraffic]
	trafficByKey      *lru.Cache[StatsTrafficKey, StatsTraffic]
	trafficBySrcIPv4  *lru.Cache[uint32, StatsTraffic]
	trafficByDstIPv4  *lru.Cache[uint32, StatsTraffic]
	trafficByVLAN     *lru.Cache[uint16, StatsTraffic]
	trafficByProtoL2  *lru.Cache[uint16, StatsTraffic]
	trafficByProtoL3  *lru.Cache[uint16, StatsTraffic]
	trafficByDstIface *lru.Cache[uint16, StatsTraffic]
}

type portStats struct {
	mutex           sync.RWMutex
	PortName        string     `json:"PortName" yaml:"PortName"`
	XdpStats        StatsXDP   `json:"XdpStats" yaml:"XdpStats"`
	XdpStatsPerCore []StatsXDP `json:"XdpStatsPerCore" yaml:"XdpStatsPerCore"`
	xdpStatsHistory list.List
	UpTimestamp     time.Time `json:"UpTimestamp" yaml:"UpTimestamp"`
	UpdatedAt       time.Time `json:"UpdatedAt" yaml:"UpdatedAt"`
	RxRate          uint64    `json:"RxRate" yaml:"RxRate"` //rate in bytes per second
	RxPackets       uint64    `json:"RxPackets" yaml:"RxPackets"`
	RxBytes         uint64    `json:"RxBytes" yaml:"RxBytes"`
	TxRate          uint64    `json:"TxRate" yaml:"TxRate"` //rate in bytes per second
	TxPackets       uint64    `json:"TxPackets" yaml:"TxPackets"`
	TxBytes         uint64    `json:"TxBytes" yaml:"TxBytes"`

	PortTraffic           StatsTraffic
	PortTrafficByCore     map[uint32]StatsTraffic
	PortTrafficByKey      map[StatsTrafficKey]StatsTraffic
	PortTrafficBySrcIPv4  map[uint32]StatsTraffic
	PortTrafficByDstIPv4  map[uint32]StatsTraffic
	PortTrafficByVLAN     map[uint16]StatsTraffic
	PortTrafficByProtoL2  map[uint16]StatsTraffic
	PortTrafficByProtoL3  map[uint16]StatsTraffic
	PortTrafficByDstIface map[uint16]StatsTraffic
	PortTrafficMutex      sync.RWMutex
}

type switchPort struct {
	driverName    string
	speed         uint32
	settings      portSettings
	iface         *net.Interface
	netlink       netlink.Link
	ethtoolHandle *ethtool.Ethtool
	ethtoolCmd    *ethtool.EthtoolCmd
	eBPF          eBPFData
	// Tap           *water.Interface //todo
	Stats   portStats
	Traffic TrafficObserver
}

type eBPFPortConfig struct {
	ifIndex     uint16
	vlanId      uint16
	vlanBitmask [64]uint64
	// vlanBitmask      [256]uint16
	mac              [6]byte
	transparent      uint16
	ingressFiltering uint16
	hookDrop         uint16
	hookEgress       uint16
	tap              uint16
}

type eBPFPortConfigGroup struct {
	configs [MAX_IFACES]eBPFPortConfig
	ifCount uint16
}

type eBPFPortCfg struct {
	if_index uint16
	vlan_id  uint16
}

type eBPFPortCfgTC struct {
	ifIndex     uint16
	vlanId      uint16
	vlanBitmask [64]uint64
	// vlanBitmask [256]uint16
}

type eBPFPortCfgTCAll struct {
	configs [MAX_IFACES]eBPFPortCfgTC
	ifCount uint16
}

type eBPFData struct {
	link *link.Link
	spec *ebpf.CollectionSpec

	internals eBPFInternals

	portCfg eBPFPortConfig
}

type StatsXDP struct {
	// mutex             sync.RWMutex
	RxDroppedBytes      uint64 `json:"RxDroppedBytes" yaml:"RxDroppedBytes"`
	RxDroppedPackets    uint64 `json:"RxDroppedPackets" yaml:"RxDroppedPackets"`
	RxPassedBytes       uint64 `json:"RxPassedBytes" yaml:"RxPassedBytes"`
	RxPassedPackets     uint64 `json:"RxPassedPackets" yaml:"RxPassedPackets"`
	RxRedirectedBytes   uint64 `json:"RxRedirectedBytes" yaml:"RxRedirectedBytes"`
	RxRedirectedPackets uint64 `json:"RxRedirectedPackets" yaml:"RxRedirectedPackets"`
	RxLastTimestamp     uint64 `json:"RxLastTimestamp" yaml:"RxLastTimestamp"`

	TxRedirectedBytes   uint64 `json:"TxRedirectedBytes" yaml:"TxRedirectedBytes"`
	TxRedirectedPackets uint64 `json:"TxRedirectedPackets" yaml:"TxRedirectedPackets"`
	TxLastTimestamp     uint64 `json:"TxLastTimestamp" yaml:"TxLastTimestamp"`
}

type StatsTrafficKey struct {
	SrcIPv4       uint32 `json:"SrcIPv4" yaml:"SrcIPv4"`
	DstIPv4       uint32 `json:"DstIPv4" yaml:"DstIPv4"`
	Vlan          uint16 `json:"Vlan" yaml:"Vlan"`
	ProtoL2       uint16 `json:"ProtoL2" yaml:"ProtoL2"`
	ProtoL3       uint16 `json:"ProtoL3" yaml:"ProtoL3"`
	TargetIfIndex uint16 `json:"TargetIfIndex" yaml:"TargetIfIndex"`
}

type LatestPacketInfo struct {
	Timestamp uint64 `json:"Timestamp" yaml:"Timestamp"`
	Tagged    uint8  `json:"Tagged" yaml:"Tagged"`
	Size      uint16 `json:"Size" yaml:"Size"`
}

func NewStatsTraffic() StatsTraffic {
	return StatsTraffic{
		mutex: sync.RWMutex{},
		LatestPacket: LatestPacketInfo{
			Timestamp: 0,
			Tagged:    0,
			Size:      0,
		},

		RxDroppedBytes:      0,
		RxDroppedPackets:    0,
		RxPassedBytes:       0,
		RxPassedPackets:     0,
		RxRedirectedBytes:   0,
		RxRedirectedPackets: 0,
	}
}

func UnmarshallStatsTraffic(trafficBytes []byte) StatsTraffic {
	return StatsTraffic{
		mutex: sync.RWMutex{},
		LatestPacket: LatestPacketInfo{
			Timestamp: binary.LittleEndian.Uint64(trafficBytes[:8]),
			Tagged:    trafficBytes[8],
			Size:      binary.BigEndian.Uint16(trafficBytes[9:11]),
		},

		RxDroppedBytes:      binary.LittleEndian.Uint64(trafficBytes[11:19]),
		RxDroppedPackets:    binary.LittleEndian.Uint64(trafficBytes[19:27]),
		RxPassedBytes:       binary.LittleEndian.Uint64(trafficBytes[27:35]),
		RxPassedPackets:     binary.LittleEndian.Uint64(trafficBytes[35:43]),
		RxRedirectedBytes:   binary.LittleEndian.Uint64(trafficBytes[43:51]),
		RxRedirectedPackets: binary.LittleEndian.Uint64(trafficBytes[51:59]),
	}
}

func (stats *StatsTraffic) Add(statsToAdd StatsTraffic) {
	stats.RxDroppedBytes += statsToAdd.RxDroppedBytes
	stats.RxDroppedPackets += statsToAdd.RxDroppedPackets
	stats.RxPassedBytes += statsToAdd.RxPassedBytes
	stats.RxPassedPackets += statsToAdd.RxPassedPackets
	stats.RxRedirectedBytes += statsToAdd.RxRedirectedBytes
	stats.RxRedirectedPackets += statsToAdd.RxRedirectedPackets
	if statsToAdd.LatestPacket.Timestamp > stats.LatestPacket.Timestamp {
		stats.LatestPacket = statsToAdd.LatestPacket
	}
}

func (stats *StatsTraffic) Sub(statsToSubtract StatsTraffic) StatsTraffic {
	ret := StatsTraffic{
		LatestPacket:        stats.LatestPacket,
		RxDroppedBytes:      stats.RxDroppedBytes - statsToSubtract.RxDroppedBytes,
		RxDroppedPackets:    stats.RxDroppedPackets - statsToSubtract.RxDroppedPackets,
		RxPassedBytes:       stats.RxPassedBytes - statsToSubtract.RxPassedBytes,
		RxPassedPackets:     stats.RxPassedPackets - statsToSubtract.RxPassedPackets,
		RxRedirectedBytes:   stats.RxRedirectedBytes - statsToSubtract.RxRedirectedBytes,
		RxRedirectedPackets: stats.RxRedirectedPackets - statsToSubtract.RxRedirectedPackets,
	}
	return ret
}

type StatsTraffic struct {
	mutex        sync.RWMutex
	LatestPacket LatestPacketInfo `json:"LatestPacket" yaml:"LatestPacket"`

	RxDroppedBytes      uint64 `json:"RxDroppedBytes" yaml:"RxDroppedBytes"`
	RxDroppedPackets    uint64 `json:"RxDroppedPackets" yaml:"RxDroppedPackets"`
	RxPassedBytes       uint64 `json:"RxPassedBytes" yaml:"RxPassedBytes"`
	RxPassedPackets     uint64 `json:"RxPassedPackets" yaml:"RxPassedPackets"`
	RxRedirectedBytes   uint64 `json:"RxRedirectedBytes" yaml:"RxRedirectedBytes"`
	RxRedirectedPackets uint64 `json:"RxRedirectedPackets" yaml:"RxRedirectedPackets"`
}

type eBPFInternals struct {
	ProgXDP *ebpf.Program `ebpf:"Prog_xdp"`
	ProgTC  *ebpf.Program `ebpf:"Prog_tc"`

	ProgTail1 *ebpf.Program `ebpf:"tail_call1"`
	ProgTail2 *ebpf.Program `ebpf:"tail_call2"`

	ProgTail1B *ebpf.Program `ebpf:"tail_call1B"`
	ProgTail2B *ebpf.Program `ebpf:"tail_call2B"`

	ProgEgressTC *ebpf.Program `ebpf:"Prog_egress_tc"`

	ProgHookDropXDP *ebpf.Program `ebpf:"hook_drop_xdp"`
	ProgHookDropTC  *ebpf.Program `ebpf:"hook_drop_tc"`

	ProgHookEgressXDP *ebpf.Program `ebpf:"hook_egress_xdp"`
	ProgHookEgressTC  *ebpf.Program `ebpf:"hook_egress_tc"`

	MapFdbXDP       *ebpf.Map `ebpf:"Map_fdb_xdp"`
	MapJumpTableXDP *ebpf.Map `ebpf:"Map_jump_table_xdp"`
	MapJumpTableTC  *ebpf.Map `ebpf:"Map_jump_table_tc"`
	MapStatsXDP     *ebpf.Map `ebpf:"Map_stats_xdp"`
	MapStatsTraffic *ebpf.Map `ebpf:"Map_stats_traffic"`
}

func (internals *eBPFInternals) Close() {
	internals.ProgTC.Close()
	internals.ProgEgressTC.Close()
	internals.ProgXDP.Close()
	internals.ProgTail1.Close()
	internals.ProgTail1B.Close()
	internals.ProgTail2.Close()
	internals.ProgTail2B.Close()
	internals.ProgHookDropXDP.Close()
	internals.ProgHookDropTC.Close()
	internals.ProgHookEgressXDP.Close()
	internals.ProgHookEgressTC.Close()
	internals.MapFdbXDP.Close()
	internals.MapStatsXDP.Close()
	internals.MapStatsTraffic.Close()
	internals.MapJumpTableXDP.Close()
	internals.MapJumpTableTC.Close()
}

func (port *switchPort) upEbpf(ifList []*switchPort) error {
	err := netlink.SetPromiscOn(port.netlink)
	if err != nil {
		return err
	}

	err = port.ethtoolHandle.Change(port.iface.Name, FEATURES_DISABLE)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(port.netlink)
	if err != nil {
		return err
	}

	port.speed, err = port.ethtoolHandle.CmdGet(port.ethtoolCmd, port.iface.Name)
	if err != nil {
		return err
	}
	if port.speed == 4294967295 { //unknown speed
		port.speed = 0
	}

	port.eBPF.spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfElf))
	if err != nil {
		return err
	}
	port.eBPF.spec.Maps["Map_fdb_xdp"].Pinning = ebpf.PinByName
	port.eBPF.spec.Maps["Map_stats_xdp"].Pinning = ebpf.PinByName
	port.eBPF.spec.Maps["Map_jump_table_xdp"].Pinning = ebpf.PinByName
	port.eBPF.spec.Maps["Map_jump_table_tc"].Pinning = ebpf.PinByName

	var portCfgVlanBitmask [64]uint64
	if port.settings.Trunk {
		portCfgVlanBitmask = bitmaskAllVlans64([]uint16{port.settings.PVID})
	} else {
		portCfgVlanBitmask = bitmaskVlanList64(port.settings.Vlans)
	}

	ingressFiltering := uint16(0)
	if port.settings.ingressFiltering {
		ingressFiltering = 1
	}

	macBytes := [6]byte{}
	copy(macBytes[:], port.iface.HardwareAddr[:6])
	transparent := uint16(0)
	if port.settings.Transparent {
		transparent = 1
	}
	hookDrop := uint16(0)
	if port.settings.HookDrop != "" {
		hookDrop = 1
	}
	hookEgress := uint16(0)
	if port.settings.HookEgress != "" {
		hookEgress = 1
	}
	portCfg := eBPFPortConfig{
		ifIndex:          uint16(port.iface.Index),
		vlanId:           port.settings.PVID,
		vlanBitmask:      portCfgVlanBitmask,
		mac:              macBytes,
		transparent:      transparent,
		ingressFiltering: ingressFiltering,
		hookDrop:         hookDrop,
		hookEgress:       hookEgress,
		tap:              uint16(0),
	}

	portCfgListByIdx := [MAX_IFACES]eBPFPortConfig{}
	portIdxList := [MAX_IFACES]uint8{}
	for idx, p := range ifList {
		var pCfgVlanBitmask [64]uint64
		if p.settings.Trunk {
			pCfgVlanBitmask = bitmaskAllVlans64([]uint16{p.settings.PVID})
		} else {
			pCfgVlanBitmask = bitmaskVlanList64(p.settings.Vlans)
		}

		ingressFiltering = uint16(0)
		if p.settings.ingressFiltering {
			ingressFiltering = 1
		}

		macBytes = [6]byte{}
		copy(macBytes[:], p.iface.HardwareAddr[:6])

		transparent = 0
		if p.settings.Transparent {
			transparent = 1
		}

		hookDrop = 0
		if p.settings.HookDrop != "" {
			hookDrop = 1
		}
		hookEgress = 0
		if p.settings.HookEgress != "" {
			hookEgress = 1
		}

		portCfgListByIdx[p.iface.Index] = eBPFPortConfig{
			ifIndex:          uint16(p.iface.Index),
			vlanId:           p.settings.PVID,
			vlanBitmask:      pCfgVlanBitmask,
			mac:              macBytes,
			transparent:      transparent,
			ingressFiltering: ingressFiltering,
			hookDrop:         hookDrop,
			hookEgress:       hookEgress,
			tap:              uint16(0),
		}

		portIdxList[idx] = uint8(p.iface.Index)
	}

	enableStats := uint8(0)
	if STATS_ENABLED {
		enableStats = 1
	}
	err = port.eBPF.spec.RewriteConstants(map[string]interface{}{
		"PORT_CFG":         portCfg,
		"PORT_COUNT":       uint8(len(ifList)),
		"PORTS_CFG_BY_IDX": portCfgListByIdx,

		"PORTS_IDX":     portIdxList,
		"STATS_ENABLED": enableStats,
	})
	if err != nil {
		panic(err)
	}

	collectionOpts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// The base path to pin maps in if requested via PinByName.
			// Existing maps will be re-used if they are compatible, otherwise an
			// error is returned.
			// PinPath: "/sys/fs/bpf/xdp_switch",
			PinPath: "/sys/fs/bpf/",
			// LoadPinOptions: ebpf.LoadPinOptions{},
		},
		// Programs: ProgramOptions,
		// MapReplacements: map[string]*ebpf.Map,
	}

	if err := port.eBPF.spec.LoadAndAssign(&port.eBPF.internals, &collectionOpts); err != nil {
		panic(err)
	}

	port.eBPF.internals.MapJumpTableTC.Put(int32(1), int32(port.eBPF.internals.ProgTail1.FD()))
	port.eBPF.internals.MapJumpTableTC.Put(int32(2), int32(port.eBPF.internals.ProgTail2.FD()))
	port.eBPF.internals.MapJumpTableTC.Put(int32(3), int32(port.eBPF.internals.ProgTail1B.FD()))
	port.eBPF.internals.MapJumpTableTC.Put(int32(4), int32(port.eBPF.internals.ProgTail2B.FD()))
	port.eBPF.internals.MapJumpTableTC.Put(int32(5), int32(port.eBPF.internals.ProgHookDropTC.FD()))
	port.eBPF.internals.MapJumpTableTC.Put(int32(6), int32(port.eBPF.internals.ProgHookEgressTC.FD()))

	port.eBPF.internals.MapJumpTableXDP.Put(int32(1), int32(port.eBPF.internals.ProgHookDropXDP.FD()))
	port.eBPF.internals.MapJumpTableXDP.Put(int32(2), int32(port.eBPF.internals.ProgHookEgressXDP.FD()))

	port.Stats.UpTimestamp = time.Now()

	err = port.attachPrograms()
	if err != nil {
		panic(err)
	}

	return nil
}

func (port *switchPort) downEbpf() error {
	fmt.Println("todo: downEbpf")
	return nil
}

func (port *switchPort) reloadEbpf() error {
	fmt.Println("todo: reloadEbpf")
	return nil
}

func xdpModeToFlag(xdpMode string) uint32 {
	switch xdpMode {
	case option.XDPModeNative:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	case option.XDPModeLinkDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeLinkGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// attachPrograms attaches progs to link.
// If xdpFlags is non-zero, attaches prog to XDP.
func (port *switchPort) attachPrograms() error {
	if port.eBPF.internals.ProgXDP != nil {
		mode := port.settings.XDPMode
		if mode == "" {
			mode = DEFAULT_XDP_MODE
		}

		err := netlink.LinkSetXdpFdWithFlags(port.netlink, port.eBPF.internals.ProgXDP.FD(), int(xdpModeToFlag(mode)))
		if err != nil { //forced, todo
			fmt.Printf("Error attaching XDP program with flag: %s. Using xdpgeneric instead.", mode)
			if DEFAULT_XDP_MODE == option.XDPModeLinkGeneric {
				port.settings.XDPMode = ""
			} else {
				port.settings.XDPMode = option.XDPModeLinkGeneric
			}
			mode = option.XDPModeLinkGeneric
			err = netlink.LinkSetXdpFdWithFlags(port.netlink, port.eBPF.internals.ProgXDP.FD(), int(xdpModeToFlag(mode)))
			if err != nil {
				return fmt.Errorf("attaching XDP program to interface %s: %w", &port.iface.Name, err)
			}
		}
	}

	if port.eBPF.internals.ProgTC != nil {
		if err := replaceQdisc(port.netlink); err != nil {
			return fmt.Errorf("replacing clsact qdisc for interface %s: %w", port.iface.Name, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: port.netlink.Attrs().Index,
				Handle:    netlink.MakeHandle(0, 1),
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
				// Priority: uint16(option.Config.TCFilterPriority),
			},
			Fd:           port.eBPF.internals.ProgTC.FD(),
			Name:         fmt.Sprintf("%s-tc-ingress-%s", PROG_NAME, port.iface.Name),
			DirectAction: true,
		}

		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter: %w", err)
		}

		// if port.settings.Tap { //todo
		// filterEgress := &netlink.BpfFilter{
		// 	FilterAttrs: netlink.FilterAttrs{
		// 		LinkIndex: port.netlink.Attrs().Index,
		// 		// Parent:    qdiscParent,
		// 		// Parent: 0xFFFF,
		// 		// Handle: netlink.MakeHandle(0xFFFF, 0),
		// 		Handle: netlink.MakeHandle(0, 1),
		// 		// Handle: uint32(1),
		// 		// Handle: uint32(0),
		// 		// Protocol: uint16(0x0003), // unix.ETH_P_ALL = 0x0003 (linux/if_ether.h)
		// 		Parent:   netlink.HANDLE_MIN_EGRESS,
		// 		Protocol: unix.ETH_P_ALL,
		// 		Priority: 1,
		// 		// Priority: uint16(option.Config.TCFilterPriority),
		// 	},
		// 	Fd:           port.eBPF.internals.ProgEgressTC.FD(),
		// 	Name:         fmt.Sprintf("%s-tc-egress-%s", PROG_NAME, port.iface.Name),
		// 	DirectAction: true,
		// }

		// if err := netlink.FilterReplace(filterEgress); err != nil {
		// 	return fmt.Errorf("replacing tc egress filter: %w", err)
		// }
		// }

	}

	return nil
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func extractDstMac(frame *[]byte) net.HardwareAddr {
	return net.HardwareAddr((*frame)[0:6])
}

func extractSrcMac(frame *[]byte) net.HardwareAddr {
	return net.HardwareAddr((*frame)[6:12])
}

func sliceRepeat[T any](size int, v T) []T {
	retval := make([]T, 0, size)
	for i := 0; i < size; i++ {
		retval = append(retval, v)
	}
	return retval
}

func divmod(numerator, denominator int64) (quotient, remainder int64) {
	quotient = numerator / denominator // integer division, decimals are truncated
	remainder = numerator % denominator
	return
}

func bitmaskVlanList64(vlans []uint16) [64]uint64 {
	var out [64]uint64
	for _, vlan := range vlans {
		vlan64 := uint64(vlan)

		section := vlan64 / 64 // integer division, decimals are truncated
		offset := vlan64 % 64  // decimal offset in range 0-63
		offsetBitmask := uint64(1) << offset

		out[section] = out[section] | offsetBitmask
	}

	return out
}

func bitmaskVlanList32(vlans []uint16) [128]uint32 {
	var out [128]uint32
	for _, vlan := range vlans {
		vlan32 := uint32(vlan)

		section := vlan32 / 32 // integer division, decimals are truncated
		offset := vlan32 % 32  // decimal offset in range 0-127
		offsetBitmask := uint32(1) << offset

		out[section] = out[section] | offsetBitmask
	}

	return out
}

func bitmaskVlanList16(vlans []uint16) [256]uint16 {
	out := [256]uint16{}
	for _, vlan := range vlans {
		section := vlan / 16 // integer division, decimals are truncated
		offset := vlan % 16  // decimal offset in range 0-255
		offsetBitmask := uint16(1) << offset

		out[section] = out[section] | offsetBitmask
	}

	return out
}

func bitmaskAllVlans16(exclude []uint16) [256]uint16 {
	out := ALL_VLANS_BITMASK_16
	for _, vlan := range exclude {
		section := vlan / 16 // integer division, decimals are truncated
		offset := vlan % 16  // decimal offset in range 0-255
		offsetBitmask := uint16(1) << offset

		out[section] = out[section] ^ offsetBitmask
	}

	return out
}

func bitmaskAllVlans64(exclude []uint16) [64]uint64 {

	out := ALL_VLANS_BITMASK_64
	for _, vlan := range exclude {
		section := vlan / 64 // integer division, decimals are truncated
		offset := vlan % 64  // decimal offset in range 0-255
		offsetBitmask := uint64(1) << offset
		out[section] = out[section] ^ offsetBitmask
	}

	return out
}

var ALL_VLANS_BITMASK_64 [64]uint64 = [64]uint64{18446744073709551614, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 18446744073709551615, 9223372036854775807}

var ALL_VLANS_BITMASK_16 [256]uint16 = [256]uint16{65534, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 32767}
