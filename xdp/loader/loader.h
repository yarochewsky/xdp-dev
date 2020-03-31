#ifndef __LOADER_H__
#define __LOADER_H__

#include <stdlib.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>


/**
	load_xdp_object_file: loads an object into obj given a filename and optional
												hw offload iface index.

	@filename: name of object file to load
	@ifindex: interface index for hw offload (specify 0 if none)
	@obj: return param for loaded object

	@returns non-zero for error
**/
int load_xdp_object_file(const char* filename, int ifindex, struct bpf_object** obj);

/**
	xdp_link_detach: detaches the current xdp program from the interface

	@ifindex: interface index of attached program
	@xdp_flags: flag modes for detaching

	@returns non-zero for error
**/
int xdp_link_detach(int ifindex, __u32 xdp_flags);

/**
	xdp_link_attach: attaches the program in fd to the interface
	
	@ifindex: interface index to attach program to
	@xdp_flags: flag modes for attaching
	@fd: file descriptor of program to attach

	@returns non-zero for error
**/
int xdp_link_attach(int ifindex, __u32 xdp_flags, int fd);


/**
	pin_object_map: pins map of obj in dir

	@obj: object containing map to pin
	@dir: directory on fs to pin map to
	@map_name: name of map to pin under dir

	@return non-zero for error
**/
int pin_object_map(struct bpf_object* obj, const char* dir, const char* map_name);

#endif // _LOADER_H
