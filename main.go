// xdp_drop.go Drop incoming packets on XDP layer and count for which
// protocol type. Based on:
// https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright (c) 2017 GustavoKatel
// Licensed under the Apache License, Version 2.0 (the "License")

package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

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

type ipv4_lpm_key struct {
	prefixlen uint32
	addr      uint32
}

//go:embed xdp_ddos.c
var source string

func loadWhitelist(path string) []ipv4_lpm_key {
	whiltelist := []ipv4_lpm_key{}
	// open file
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	// read each line of the file, and append it to the whitelist
	// each line has format 1.2.3.4/24
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var prefixlen uint32
		var addr [4]uint32
		fmt.Sscanf(scanner.Text(), "%d.%d.%d.%d/%d", &addr[0], &addr[1], &addr[2], &addr[3], &prefixlen)
		var ip uint32
		// convert from ip string to uint32
		ip = addr[3]<<24 | addr[2]<<16 | addr[1]<<8 | addr[0]
		// fmt.Printf("cidr: 0x%08x/%d\n", ip, prefixlen)
		whiltelist = append(whiltelist, ipv4_lpm_key{prefixlen: prefixlen, addr: ip})
	}
	return whiltelist
}

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
	blacklist := bpf.NewTable(module.TableId("whitelist"), module)
	port_blacklist := bpf.NewTable(module.TableId("port_blacklist"), module)
	port_blacklist_drop_count_tcp := bpf.NewTable(module.TableId("port_blacklist_drop_count_tcp"), module)
	port_blacklist_drop_count_udp := bpf.NewTable(module.TableId("port_blacklist_drop_count_udp"), module)
	verdict_cnt := bpf.NewTable(module.TableId("verdict_cnt"), module)

	var asByteSlice []byte
	var value uint32 = 0x00
	// load whitelist
	whitelist := loadWhitelist("whitelist.txt")
	for _, v := range whitelist {
		asByteSlice = (*(*[16]byte)(unsafe.Pointer(&ipv4_lpm_key{prefixlen: v.prefixlen, addr: v.addr})))[:]
		blacklist.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
		value += 1
	}
	fmt.Println("values", value)
	asByteSlice = (*(*[16]byte)(unsafe.Pointer(&ipv4_lpm_key{prefixlen: 24, addr: 0x01010b0a})))[:]
	blacklist.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
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
