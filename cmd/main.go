package main

import (
	"log"
	"flag"

	"github.com/yarochewsky/xdp-dev/internal/loader"
)
const (
	file = "xdp/elfs/pass_drop.o"
	sec = "xdp/xdp_drop"
)

var (
	iface = flag.String("iface", "", "interface to attach program to")
)

func main() {
	flag.Parse()

	l := loader.New()
	if err := l.Load(file); err != nil {
		log.Fatalln("failed to load file: ", err)
	}
	if err := l.Attach(*iface, sec); err != nil {
		log.Fatalln("failed to attach: ", err)
	}
}
