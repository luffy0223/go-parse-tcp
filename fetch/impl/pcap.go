package impl

import (
	"encoding/json"
	"fetch/conf"
	"fetch/utils"
	"fmt"
	"github.com/Shopify/sarama"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type PacketStrut struct {
	CaptureInfo gopacket.CaptureInfo
	PcapData    []byte
}

var exitPcapChan = make(chan bool, 5)
var snapshotLen int32 = 1526
var timeout time.Duration = 30 * time.Second

func Fetch(fetchDevice, fetchProtocol, fetchBeginTime, fetchPort string, fetchDuring int) {

	//创建计时器，等待至采集开始时间
	timer := time.NewTicker(calTimeToWait(fetchBeginTime))
	<-timer.C
	OpenPacket(fetchDevice, fetchPort, fetchDuring)

}

func calTimeToWait(begin string) time.Duration {
	t1, _ := utils.Transfer2Time(begin)
	return t1.Sub(time.Now())
}

func OpenPacket(fetchDevice, fetchPort string, fetchDuring int) {
	go exitTimer(fetchDuring)
	signExit()
	handle, err := pcap.OpenLive(fetchDevice, snapshotLen, false, timeout)
	if err != nil {
		fmt.Println("open pcap error! errmsg:", err.Error())
	}
	defer handle.Close()

	filter := "tcp and port " + fetchPort
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("set BPFFilter error! errmsg", err.Error())
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()
	var i = 0
PACKETLOOP:
	for {
		select {
		case <-exitPcapChan:
			break PACKETLOOP
		case packet := <-packetChan:
			select {
			case <-exitPcapChan:
				break PACKETLOOP
			default:
				fmt.Println("break select ", i)
				i++
				break
			}
			fmt.Println(len(packetChan))
			pcapContent(packet, fetchDevice)
		}
	}
}

func exitTimer(fetchDuring int) {
	timer := time.NewTicker(time.Duration(fetchDuring) * time.Second)
	<-timer.C
	exitPcap()
}

func exitPcap() {
	exitPcapChan <- true
}

func signExit() {
	exit := make(chan os.Signal)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		c, _ := <-exit
		fmt.Println("signal:" + c.String())
		exitPcap()
	}()
}

func pcapContent(packet gopacket.Packet, fetchDevice string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		//write into kafka ds
		pcapStruct := &PacketStrut{}
		pcapStruct.CaptureInfo = packet.Metadata().CaptureInfo
		pcapStruct.PcapData = packet.Data()

		fmt.Println(string(pcapStruct.PcapData))
		parsePcap(pcapStruct)
		//send2Kafka(pcapStruct)
	}
}

func parsePcap(pcapStuct *PacketStrut) {
	buf := pcapStuct.PcapData
	if len(buf) > 0 {
		fmt.Println("---------")
	}

}

func send2Kafka(pcapStruct *PacketStrut) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Partitioner = sarama.NewRandomPartitioner
	config.Producer.Return.Successes = true
	//生产者
	client, err := sarama.NewSyncProducer([]string{conf.KAFKA_ADDRESS}, config)
	if err != nil {
		fmt.Println("producer close,err:", err)
		return
	}

	defer client.Close()

	json, e := json.Marshal(pcapStruct)
	if e != nil {
		fmt.Println(e)
		return
	}
	//创建消息
	msg := &sarama.ProducerMessage{}
	msg.Topic = "my-topic"
	msg.Value = sarama.StringEncoder(string(json))
	//发送消息
	pid, offset, err := client.SendMessage(msg)
	if err != nil {
		fmt.Println("send message failed,", err)
		return
	}
	fmt.Printf("pid:%v offset:%v\n,", pid, offset)
	time.Sleep(10 * time.Millisecond)

}
