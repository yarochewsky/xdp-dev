package main

import (
	"log"

	"github.com/yarochewsky/xdp-dev/internal/loader"
)
const (
	file = "xdp/elfs/drop.o"
	iface = "vethf1812f4"
	sec = "xdp/xdp_drop"
)

func main() {
	l := loader.New()
	if err := l.Load(file); err != nil {
		log.Fatalln("failed to load file: ", err)
	}
	if err := l.Attach(iface, sec); err != nil {
		log.Fatalln("failed to attach: ", err)
	}
}
