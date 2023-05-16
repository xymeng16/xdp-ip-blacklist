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
	"log"
	"net"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/tmthrgd/go-popcount"
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

type ipv6_lpm_key struct {
	prefixlen uint32
	addr      [16]byte
}

//go:embed xdp_ip_whitelist.c
var source string

func loadIPV4Whitelist(path string) []ipv4_lpm_key {
	log.Println("loading IPv4 whitelist from", path)
	whiltelist := []ipv4_lpm_key{}
	// open file
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read each line of the file, and append it to the whitelist
	// each line has format 1.2.3.4/24
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		count += 1
		if line == "" {
			log.Println("skip empty line", count)
			os.Stdout.Sync()
			continue
		}
		if line[0] == '#' {
			log.Println("skip comment line", count)
			os.Stdout.Sync()
			continue
		}
		var prefixlen uint32
		var addr [4]uint32
		fmt.Sscanf(line, "%d.%d.%d.%d/%d", &addr[0], &addr[1], &addr[2], &addr[3], &prefixlen)
		var ip uint32
		// convert from ip string to uint32
		ip = addr[3]<<24 | addr[2]<<16 | addr[1]<<8 | addr[0]
		// fmt.Printf("cidr: 0x%08x/%d\n", ip, prefixlen)
		whiltelist = append(whiltelist, ipv4_lpm_key{prefixlen: prefixlen, addr: ip})
	}
	return whiltelist
}

func loadIPV6Whitelist(path string) []ipv6_lpm_key {
	log.Println("loading IPv6 whitelist from", path)
	whiltelist := []ipv6_lpm_key{}
	// open file
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read each line of the file, and append it to the whitelist
	// each line has format 1.2.3.4/24
	// jump empty lines and lines starting with #
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		count++
		if line == "" {
			log.Println("skip empty line", count)
			os.Stdout.Sync()
			continue
		}
		if line[0] == '#' {
			log.Println("skip comment line", count)
			os.Stdout.Sync()
			continue
		}
		//var prefixlen uint32
		//var addr [4]uint32
		addr, cidr, err := net.ParseCIDR(line)
		if err != nil {
			log.Fatal(err)
		}

		prefixlen := popcount.CountBytes(cidr.Mask)
		//fmt.Println(addr, prefixlen)
		whiltelist = append(whiltelist, ipv6_lpm_key{prefixlen: uint32(prefixlen), addr: [16]byte(addr)})
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
	ipv4_blacklist_map := bpf.NewTable(module.TableId("ipv4_whitelist"), module)
	ipv4_blocked := bpf.NewTable(module.TableId("ipv4_blocked"), module)
	ipv6_blacklist_map := bpf.NewTable(module.TableId("ipv6_whitelist"), module)
	ipv6_blocked := bpf.NewTable(module.TableId("ipv6_blocked"), module)

	var asByteSlice []byte
	var value uint32 = 0x00
	// load whitelist
	ipv4_whitelist := loadIPV4Whitelist("whitelist_v4.txt")
	ipv6_whitelist := loadIPV6Whitelist("whitelist_v6.txt")
	for _, v := range ipv4_whitelist {
		asByteSlice = (*(*[8]byte)(unsafe.Pointer(&ipv4_lpm_key{prefixlen: v.prefixlen, addr: v.addr})))[:]
		ipv4_blacklist_map.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
		value++
	}
	fmt.Println("values", value)

	// add LAN IPv4 address 10.0.0.0/24
	//asByteSlice = (*(*[8]byte)(unsafe.Pointer(&ipv4_lpm_key{prefixlen: 24, addr: 0x0000000a})))[:]
	//ipv4_blacklist_map.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
	//value++

	value = 0
	for _, v := range ipv6_whitelist {
		asByteSlice = (*(*[20]byte)(unsafe.Pointer(&ipv6_lpm_key{prefixlen: v.prefixlen, addr: v.addr})))[:]
		ipv6_blacklist_map.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
		value++
	}

	// debugging purpose fc00:dead:cafe::1/64
	// ipv6 address format __u8[16], __be16[8], __be32[4]
	/* in-header representation in __be32[4]:
	ip6h->saddr.in6_u.u6_addr32[0] = 0xadde00fc
	ip6h->saddr.in6_u.u6_addr32[1] = 0x0000feca
	ip6h->saddr.in6_u.u6_addr32[2] = 0x00000000
	ip6h->saddr.in6_u.u6_addr32[3] = 0x02000000
	*/

	// add LAN IPv6 address fd9d:4428:1767::1/60 -> fd9d:4428:1767:0000:0000:0000:0000:0000/60
	asByteSlice = (*(*[20]byte)(unsafe.Pointer(&ipv6_lpm_key{prefixlen: 60, addr: [16]byte{0x9d, 0xfd, 0x44, 0x28,
		0x17, 0x67}})))[:]
	ipv6_blacklist_map.Set(asByteSlice, (*(*[4]byte)(unsafe.Pointer(&value)))[:])
	value++

	<-sig

	//cfg := ipv4_blacklist_map.Config()
	//log.Printf("name: %s, fd: %d\n", cfg["name"], cfg["fd"])

	for it := ipv4_blocked.Iter(); it.Next(); {
		key := it.Key()
		value := bpf.GetHostByteOrder().Uint64(it.Leaf())
		log.Printf("%d.%d.%d.%d: %d\n", key[0], key[1], key[2], key[3], value)
	}
	for it := ipv6_blocked.Iter(); it.Next(); {
		_ = it.Key()
		_ = bpf.GetHostByteOrder().Uint64(it.Leaf())
		//fmt.Printf("%d.%d.%d.%d: %d\n", key[0], key[1], key[2], key[3], value)
	}
}
