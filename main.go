package main

import (
	"log"

	"github.com/yarochewsky/xdp-dev/loader"
)

const (
	file = "xdp/elfs/drop.o"
	iface = "vethf1812f4"
	sec = "xdp/xdp_drop"
)

func main() {
	l := loader.New()
	if err := l.Attach(file); err != nil {
		log.Fatalln("failed to attach file: ", err)
	}
	if err := l.Load(iface, sec); err != nil {
		log.Fatalln("failed to load: ", err)
	}
}
