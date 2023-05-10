// xdp_drop.go Drop incoming packets on XDP layer and count for which
// protocol type. Based on:
// https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright (c) 2017 GustavoKatel
// Licensed under the Apache License, Version 2.0 (the "License")

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

//go:embed xdp_ddos.c
var source string

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func main() {
	var device string

	if len(os.Args) != 2 {
		usage()
	}

	device = os.Args[1]

	ret := "XDP_DROP"
	ctxtype := "xdp_md"

	module := bpf.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})
	defer module.Close()

	fn, err := module.Load("xdp_ip_blocker", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Println("IP Blocker working, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)
	blacklist := bpf.NewTable(module.TableId("blacklist"), module)
	port_blacklist := bpf.NewTable(module.TableId("port_blacklist"), module)
	port_blacklist_drop_count_tcp := bpf.NewTable(module.TableId("port_blacklist_drop_count_tcp"), module)
	port_blacklist_drop_count_udp := bpf.NewTable(module.TableId("port_blacklist_drop_count_udp"), module)
	verdict_cnt := bpf.NewTable(module.TableId("verdict_cnt"), module)

	<-sig

	// fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
	// for it := dropcnt.Iter(); it.Next(); {
	// 	key := bpf.GetHostByteOrder().Uint32(it.Key())
	// 	value := bpf.GetHostByteOrder().Uint64(it.Leaf())

	// 	if value > 0 {
	// 		fmt.Printf("%v: %v pkts\n", key, value)
	// 	}
	// }
	// cfg := module.TableDesc(uint64(module.TableId("blacklist")))
	cfg := blacklist.Config()
	fmt.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

	cfg = port_blacklist.Config()
	fmt.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

	cfg = port_blacklist_drop_count_tcp.Config()
	fmt.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

	cfg = port_blacklist_drop_count_udp.Config()
	fmt.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

	cfg = verdict_cnt.Config()
	fmt.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

}
