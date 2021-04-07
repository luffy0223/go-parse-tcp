package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"os"
)

var (
	pcapFile string = "/Users/luffy/developer/wireshark_folder/pcap_file_20210404.pcap"
	handle   *pcap.Handle
	err      error
)


/*func main()  {

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil { log.Fatal(err) }
	defer handle.Close()
	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}*/

func main()  {
	f,err :=os.Open(pcapFile)
	if err!=nil{
		fmt.Println(err)
		return
	}
	defer  f.Close()
	buf :=make([]byte,1024)
	for{
		n,_ := f.Read(buf)
		if n==0 {
			break
		}
	}

}