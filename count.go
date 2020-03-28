package main

import (
	"bytes"
	"time"
	"log"
	"flag"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/yarochewsky/xdp-dev/internal/loader"

	gobpf "github.com/iovisor/gobpf/elf"
)

var (
	iface = flag.String("iface", "", "interface to attach program to")
)

func main() {
	flag.Parse()

	l := loader.New()
	if err := l.Load("xdp/elfs/ipv4.o"); err != nil {
		log.Fatalln("failed to load file: ", err)
	}
	if err := l.Attach(*iface, "xdp/ip_block"); err != nil {
		log.Fatalln("failed to attach: ", err)
	}
	mod := l.Current()
	counterMap, err := loadMap(mod, "xdp_stats_map")
	if err != nil {
		log.Fatal(err)
	}
	var value uint32
	key := 2

	for {
		if err := mod.LookupElement(counterMap, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			fmt.Println(err)
		}
		buffer := bytes.NewBuffer([]byte{})
		if err := binary.Write(buffer, binary.LittleEndian, value); err != nil {
			continue
		}
		fmt.Println(value)
		time.Sleep(5)
	}
}

func loadMap(mod *gobpf.Module, name string) (*gobpf.Map, error) {
	counterMap := mod.Map("xdp_stats_map")
	if counterMap  == nil {
		return nil, fmt.Errorf("unable to find map ", name)
	}
	return counterMap, nil
}
