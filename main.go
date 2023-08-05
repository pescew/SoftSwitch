package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/option"
	json "github.com/goccy/go-json"
	"gopkg.in/yaml.v3"
)

const DEBUG = false
const PROG_NAME = "SoftSwitch"
const PROG_VERSION = 0.1

// const TAP_DEV_PREFIX = ""

// const DEFAULT_XDP_MODE = option.XDPModeLinkGeneric
const DEFAULT_XDP_MODE = option.XDPModeLinkDriver

//go:embed ebpf/prog.elf
var ebpfElf []byte

type Configuration struct {
	Version    float64                 `json:"version" yaml:"version"`
	Interfaces map[string]portSettings `json:"interfaces" yaml:"interfaces"`
}

func (cfg *Configuration) Build() (*BridgeGroup, error) {
	ports := &BridgeGroup{
		ifMap:        make(map[string]*switchPort),
		ifMapByIndex: make(map[uint16]*switchPort),
		ifList:       []*switchPort{},
	}
	for ifName, ifSettings := range cfg.Interfaces {
		ifSettings.Validate()

		err := ports.addPort(ifName, ifSettings)
		if err != nil {
			return nil, err
		}
	}

	if len(ports.ifMap) < 2 {
		return nil, fmt.Errorf("Bridge must have at least 2 network interfaces")
	}

	ports.ifList = ports.buildPortList()

	return ports, nil
}

func (cfg *Configuration) LoadFromFile(fileName string) error {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	if strings.HasSuffix(strings.ToLower(fileName), ".json") {
		err = cfg.LoadFromJSON([]byte(file))
	} else {
		err = cfg.LoadFromYAML([]byte(file))
	}
	if err != nil {
		return err
	}
	return nil
}

func (cfg *Configuration) LoadFromJSON(jsonBytes []byte) error {
	err := json.Unmarshal(jsonBytes, &cfg)
	if err != nil {
		return err
	}
	return nil
}

func (cfg *Configuration) LoadFromYAML(yamlBytes []byte) error {
	err := yaml.Unmarshal(yamlBytes, &cfg)
	if err != nil {
		return err
	}
	return nil
}

func (cfg *Configuration) ExportToFile(fileName string) error {
	var err error
	var fileBytes []byte
	if strings.HasSuffix(strings.ToLower(fileName), ".json") {
		fileBytes, err = cfg.ExportToJSON()
	} else {
		fileBytes, err = cfg.ExportToYAML()
	}
	if err != nil {
		return err
	}
	err = os.WriteFile(fileName, fileBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (cfg *Configuration) ExportToJSON() ([]byte, error) {
	jsonBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return []byte{}, err
	}
	return jsonBytes, nil
}

func (cfg *Configuration) ExportToYAML() ([]byte, error) {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return []byte{}, err
	}
	return yamlBytes, nil
}

func (cfg *Configuration) AddPort(interfaceName string, trunk bool, pvid uint16, vlans []uint16, xdpMode string, tap, transparent, ingressFiltering bool, hookDrop, hookEgress string) {
	cfg.Interfaces[interfaceName] = portSettings{
		Trunk:   trunk,
		PVID:    pvid,
		Vlans:   vlans,
		XDPMode: xdpMode,
		// Tap:              tap, //todo
		Transparent:      transparent,
		ingressFiltering: ingressFiltering,
		HookDrop:         hookDrop,
		HookEgress:       hookEgress,
	}
}

func (cfg *Configuration) RemovePort(interfaceName string) {
	delete(cfg.Interfaces, interfaceName)
}

func ExitWithError(err error) {
	if DEBUG {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

type flagPortList []string

func (list *flagPortList) String() string {
	str := ""
	for _, port := range *list {
		str += fmt.Sprintf(" %s", port)
	}
	return str
}

func (list *flagPortList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func (list *flagPortList) Parse() (map[string]portSettings, error) {
	var err error
	ifaces := make(map[string]portSettings)
	for _, port := range *list {
		ifName := ""
		ifPVID := uint64(0)
		ifVLANs := []uint16{}
		ifTrunk := false
		// tap := false
		transparent := false
		ingressFiltering := true
		hookDrop := ""
		hookEgress := ""
		xdpMode := ""

		portExpanded := strings.Split(port, ",")
		for index, val := range portExpanded {
			switch index {
			case 0:
				ifName = val
			default:
				switch strings.ToLower(val) {
				case "transparent":
					transparent = true
				// case "tap", "tun":
				// 	tap = true
				case "hookdrop":
					hookDrop = "todo: elf file name"
				case "hookegress":
					hookEgress = "todo: elf file name"
				case "trunk":
					ifTrunk = true
					ingressFiltering = false
				case option.XDPModeLinkDriver:
					if DEFAULT_XDP_MODE == option.XDPModeLinkDriver {
						xdpMode = ""
					} else {
						xdpMode = option.XDPModeLinkDriver
					}
					xdpMode = option.XDPModeLinkDriver
				case option.XDPModeLinkGeneric:
					if DEFAULT_XDP_MODE == option.XDPModeLinkGeneric {
						xdpMode = ""
					} else {
						xdpMode = option.XDPModeLinkGeneric
					}
				default:
					vlan, err := strconv.ParseUint(val, 10, 16)
					if err != nil {
						return nil, err
					}

					if vlan < 1 || vlan > 4094 {
						return nil, fmt.Errorf("VLAN outside range 1-4094: %s", val)
					}

					if ifPVID == 0 {
						ifPVID = vlan
					} else {
						ifVLANs = append(ifVLANs, uint16(vlan))
					}

				}
			}
		}

		if ifPVID == 0 {
			ifPVID = 1
		}

		iface := portSettings{
			Trunk:   ifTrunk, //todo
			PVID:    uint16(ifPVID),
			Vlans:   ifVLANs,
			XDPMode: xdpMode,
			// Tap:              tap,
			Transparent:      transparent,
			ingressFiltering: ingressFiltering,
			HookDrop:         hookDrop,
			HookEgress:       hookEgress,
		}

		iface.Validate()

		ifaces[ifName] = iface
	}

	return ifaces, err
}

type cmdArgs struct {
	Port map[string]bool
}

func (cmdArgs) Version() string {
	return fmt.Sprintf("%s v%f", PROG_NAME, PROG_VERSION)
}

func main() {
	var err error

	flagConfig := flag.String("config", "config.yaml", "read switch configuration from json or yaml file")
	flagDumpConfig := flag.String("dump", "", "dump switch configuration to json or yaml file")
	var flagPorts flagPortList
	flag.Var(&flagPorts, "port", "manually configure switch ports with command line flags\nex: -port eth0 -port eth1,trunk -port eth2,10 -port eth3,1,10,xdpgeneric\nports are provided as comma separated strings\nfirst element defines the network interface to use\nfirst number defines the pvid/untagged vlan\nsubsequent numbers define tagged vlans")
	flagDown := flag.Bool("down", false, "bring switch down")
	flag.Parse()

	if *flagDown {
		err = DownAll()
		if err != nil {
			ExitWithError(err)
		}
		os.Exit(0)
	}

	config := Configuration{
		Version:    PROG_VERSION,
		Interfaces: make(map[string]portSettings),
	}

	if len(flagPorts) > 0 {
		config.Interfaces, err = flagPorts.Parse()
		if err != nil {
			ExitWithError(err)
		}
	} else if strings.HasSuffix(strings.ToLower(*flagConfig), ".json") {
		err = config.LoadFromFile(*flagConfig)
		if err != nil {
			ExitWithError(err)
		}
	} else if strings.HasSuffix(strings.ToLower(*flagConfig), ".yaml") || strings.HasSuffix(strings.ToLower(*flagConfig), ".yml") {
		err = config.LoadFromFile(*flagConfig)
		if err != nil {
			ExitWithError(err)
		}
	} else {
		err = config.LoadFromJSON([]byte(*flagConfig))
		if err != nil {
			err = config.LoadFromYAML([]byte(*flagConfig))
			if err != nil {
				ExitWithError(err)
			}
		}
	}

	if *flagDumpConfig != "" {
		fmt.Printf("Dumping config to file: %s\n", *flagDumpConfig)
		err = config.ExportToFile(*flagDumpConfig)
		if err != nil {
			ExitWithError(err)
		}
	}

	bridge, err := config.Build()
	if err != nil {
		ExitWithError(err)
	}

	err = bridge.Up()
	if err != nil {
		ExitWithError(err)
	}

	fmt.Println(bridge.prettyPrint())

	os.Exit(0)

}
