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
	"github.com/google/gopacket/pcapgo"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type PacketStruct struct {
	FiveElementNode string
	PcapData        []byte
	TimeStamp       time.Time
}

var HTTPTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second, // 连接超时时间
		KeepAlive: 60 * time.Second, // 保持长连接的时间
	}).DialContext, // 设置连接的参数
	MaxIdleConns:          10,               // 最大空闲连接
	IdleConnTimeout:       60 * time.Second, // 空闲连接的超时时间
	ExpectContinueTimeout: 30 * time.Second, // 等待服务第一个响应的超时时间
	MaxIdleConnsPerHost:   10,               // 每个host保持的空闲连接数
}
var HttpClient = http.Client{Transport: HTTPTransport}
var destUrl = "http://127.0.0.1:9999/update"
var exitPcapChan = make(chan bool, 5)
var snapshotLen int32 = 1526
var timeout time.Duration = 30 * time.Second

type Glimit struct {
	n int
	c chan struct{}
}

// initialization Glimit struct
func New(n int) *Glimit {
	return &Glimit{
		n: n,
		c: make(chan struct{}, n),
	}
}

// Run f in a new goroutine but with limit.
func (g *Glimit) Run(f func()) {
	g.c <- struct{}{}
	go func() {
		f()
		<-g.c
	}()
}

var wg = sync.WaitGroup{}

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
	g := New(10)
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
				i++
				break
			}
			fmt.Println("packetchan length :", len(packetChan))
			//go pcapContent(packet, fetchDevice)
			wg.Add(1)
			goFunc := func() {
				pcapContent(packet, fetchDevice)
				wg.Done()
			}
			g.Run(goFunc)
		}
	}
	wg.Wait()
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

	var srcIP string
	var dstIP string
	var protocol byte
	var protocolType string
	var srcPort string
	var dstPort string
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.Contents[9]
	}
	if protocol == 6 {
		protocolType = "TCP"
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		//if port =80  then tcp.SrcPort.String:80(http)
		srcPort = strings.Split(tcp.SrcPort.String(), "(")[0]
		dstPort = strings.Split(tcp.DstPort.String(), "(")[0]
		srcPort = strings.Split(srcPort, "(")[0]
	}

	pcapStruct := &PacketStruct{
		FiveElementNode: generateFiveElementNode(srcIP, dstIP, srcPort, dstPort, protocolType),
		PcapData:        packet.Data(),
		TimeStamp:       packet.Metadata().Timestamp,
	}
	//pcapStruct.CaptureInfo = packet.Metadata().CaptureInfo
	send2Route(pcapStruct)
	//write into kafka ds
	//write2File(packet)
	//readFile("/Users/luffy/developer/go/go-parse-tcp/resource/dump.pcap")
	//parsePcap(pcapStruct)

	//send2Kafka(pcapStruct)

}

func send2Route(pcapStruct *PacketStruct) {
	fmt.Println("五元组为：" + pcapStruct.FiveElementNode)
	json, e := json.Marshal(pcapStruct)
	if e != nil {
		return
	}
	bodyStr := strings.NewReader(string(json))
	req, err := http.NewRequest("POST", destUrl, bodyStr)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("fiveElementNode", pcapStruct.FiveElementNode)
	res, err := HttpClient.Do(req)
	if err != nil {
		return
	}
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	res.Body.Close()
	fmt.Println("return code:" + string(res.StatusCode))
	if res.StatusCode != 200 {
		fmt.Println(res.Status)
	}
}

func generateFiveElementNode(srcIP string, dstIp string, srcPort string, dstPort string, protocol string) string {
	var str []string = []string{srcIP, dstIp, srcPort, dstPort, protocol}
	//调用Join函数
	return strings.Join(str, "_")

}

func write2File(packet gopacket.Packet) {
	dumpFile, _ := os.Create("/Users/luffy/developer/go/go-parse-tcp/resource/dump.pcap")
	defer dumpFile.Close()
	//	准备好写入的 Writer
	packetWriter := pcapgo.NewWriter(dumpFile)
	packetWriter.WriteFileHeader(
		1526, //	Snapshot length
		layers.LinkTypeEthernet,
	)
	//	写入包
	packetWriter.WritePacket(
		packet.Metadata().CaptureInfo,
		packet.Data(),
	)
}

func readFile(pcapFile string) {
	f, err := os.Open(pcapFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	buf := make([]byte, 1024)
	for {
		n, _ := f.Read(buf)
		if n == 0 {
			break

		}

	}
}

func parsePcap(pcapStuct *PacketStruct) {
	buf := pcapStuct.PcapData
	if len(buf) > 0 {
		fmt.Println("---------")
	}

}

func send2parse(pcapStruct *PacketStruct) {
	client := http.DefaultClient

	json, e := json.Marshal(pcapStruct)
	str := strings.NewReader(string(json))
	if e != nil {
		return
	}
	req, err := http.NewRequest("post", "http://127.0.0.1:9999/update", str)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Connection", "keep-alive")
	res, err := client.Do(req)
	if err != nil {
		return
	}
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	res.Body.Close()

}

func send2Kafka(pcapStruct *PacketStruct) {
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
