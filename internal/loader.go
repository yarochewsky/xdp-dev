package loader

import (
	"errors"
	"ioutil"
	"bytes"

	gobpf "github.com/iovisor/gobpf/elf"
)

type Hook interface {
	Load(elf string) error
	Attach(iface, sec string) error
	Detach() error
}

type hook struct {
	module *gobpf.Module
	iface string
	sec string
}


func New() Hook {
	return &hook{}
}

func (h *hook) Load(elf string) error {
	data, err := ioutil.ReadFile(elf)
	if err != nil {
		return err
	}
	module := gobpf.NewModuleFromReader(bytes.NewReader(data))
	if module == nil {
		return errors.New("failed to establish module for elf")
	}
	if err := module.Load(nil); err != nil {
		return err
	}
	h.module = module
	return nil
}

func (h *hook) Attach(iface, sec string) error {
	h.module.iface = iface
	h.module.sec = sec
	return h.module.AttachXDP(iface, sec)
}

func (h *hook) Detach() error {
	if err := h.module.RemoveXDP(h.iface); err != nil {
		return err
	}
	h.module = nil
	h.iface = ""
	h.sec = ""
	return nil
}
