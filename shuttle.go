package main

import (
	"fmt"
	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
	"os"
	"io"
)

func main() {

	var err error

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	in, out := io.Pipe()
	defer in.Close()
	defer out.Close()

	go func() {
		io.Copy(os.Stdout, in)
	}()

	for true {
		select {
		case p := <-packets:
			fmt.Println(p.Packet)
			fmt.Println(p.Packet.Dump())
			out.Write(p.Packet.Data())
			p.SetVerdict(netfilter.NF_STOLEN)
		}
	}
}
