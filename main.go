package main

import (
	"log"
	"bytes"
	"io/ioutil"

	gobpf "github.com/iovisor/gobpf/elf"
)

const (
	file = "xdp/elfs/drop.o"
	iface = "vethf1812f4"
	sec = "xdp/xdp_drop"
)

func main() {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal("elf not found")
	}
  module := gobpf.NewModuleFromReader(bytes.NewReader(data))
	if module == nil {
		log.Fatal("failed to establish module for elf")
	}
	if err := module.Load(nil); err != nil {
		log.Fatalln("failed to load module", err)
	}
	if err := module.AttachXDP(iface, sec); err != nil {
		log.Fatalln("failed to attach program:", err)
	}
}
