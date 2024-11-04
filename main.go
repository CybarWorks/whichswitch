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
	handle, err := pcap.OpenLive("\\Device\\NPF_{7F5895D5-F780-42AC-A8AE-F6084412AB4B}", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo); cdpLayer != nil {
			cdp, _ := cdpLayer.(*layers.CiscoDiscoveryInfo)
			fmt.Printf("DeviceID: %s \tAddress: %s \nPlatform: %s Version: %s  \n PortID: %s\n", cdp.DeviceID, cdp.Addresses, cdp.Platform, cdp.Version, cdp.PortID)
			return
		}
	}
}
