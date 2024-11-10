package main

import (
	"fmt"
	"log"
)

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle := getNetworkDevice()
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo); cdpLayer != nil {
			cdp, _ := cdpLayer.(*layers.CiscoDiscoveryInfo)
			fmt.Printf("-CDP-\nDeviceID: %s \tAddress: %s \nPlatform: %s \nVersion: %s  \n PortID: %s\n", cdp.DeviceID, cdp.Addresses, cdp.Platform, cdp.Version, cdp.PortID)
			return
		}
		if lldapLayer := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo); lldapLayer != nil {
			lldp, _ := lldapLayer.(*layers.LinkLayerDiscoveryInfo)
			fmt.Printf("-LLDP-\nSwitch Name: %s \tAddress: %s\n Platform: %s\n PortID: %s\n", lldp.SysName, convertToIP(lldp.MgmtAddress.Address), lldp.SysDescription, lldp.PortDescription)
			return
		}
	}
}

func getNetworkDevice() *pcap.Handle {
	intfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	//for _, i := range intfaces {
	//	fmt.Printf("Interface: %s\n Address: %s\n Flags: %v\n Description: %s\n", i.Name, i.Addresses, i.Flags, i.Description)
	//}
	for idx, i := range intfaces {
		fmt.Printf("%d: %s\n    Address: %s\n", idx, i.Description, i.Addresses)
	}
	fmt.Printf("Enter interface number: ")
	var input int
	fmt.Scanf("%d", &input)
	if input < 0 || input >= len(intfaces) {
		log.Fatal("Invalid interface number")
	}
	fmt.Printf("Using interface: %s\n", intfaces[input].Name)

	//handle, err := pcap.OpenLive("\\Device\\NPF_{7F5895D5-F780-42AC-A8AE-F6084412AB4B}", 1600, true, pcap.BlockForever)
	handle, err := pcap.OpenLive(intfaces[input].Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func convertToIP(address []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", address[0], address[1], address[2], address[3])
}
