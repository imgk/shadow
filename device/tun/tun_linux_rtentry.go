// +build ignore

package main

// #include <stdio.h>
// #include <net/route.h>
import "C"

import (
        "fmt"
        "unsafe"

        "golang.org/x/sys/unix"
)

func main() {
        r1 := C.struct_rtentry{}
        fmt.Println(unsafe.Sizeof(r1))
        fmt.Println("rt_pad1", unsafe.Offsetof(r1.rt_pad1))
        fmt.Println("rt_dst", unsafe.Offsetof(r1.rt_dst))
        fmt.Println("rt_gateway", unsafe.Offsetof(r1.rt_gateway))
        fmt.Println("rt_genmask", unsafe.Offsetof(r1.rt_genmask))
        fmt.Println("rt_flags", unsafe.Offsetof(r1.rt_flags))
        fmt.Println("rt_pad2", unsafe.Offsetof(r1.rt_pad2))
        fmt.Println("rt_pad3", unsafe.Offsetof(r1.rt_pad3))
        fmt.Println("rt_pad4", unsafe.Offsetof(r1.rt_pad4))
        fmt.Println("rt_metric", unsafe.Offsetof(r1.rt_metric))
        fmt.Println("rt_dev", unsafe.Offsetof(r1.rt_dev))
        fmt.Println("rt_mtu", unsafe.Offsetof(r1.rt_mtu))
        fmt.Println("rt_window", unsafe.Offsetof(r1.rt_window))
        fmt.Println("rt_irtt", unsafe.Offsetof(r1.rt_irtt))

        fmt.Println("")

        r2 := rtEntry{}
        fmt.Println(unsafe.Sizeof(r2))
        fmt.Println("rt_pad1", unsafe.Offsetof(r2.rt_pad1))
        fmt.Println("rt_dst", unsafe.Offsetof(r2.rt_dst))
        fmt.Println("rt_gateway", unsafe.Offsetof(r2.rt_gateway))
        fmt.Println("rt_genmask", unsafe.Offsetof(r2.rt_genmask))
        fmt.Println("rt_flags", unsafe.Offsetof(r2.rt_flags))
        fmt.Println("rt_pad2", unsafe.Offsetof(r2.rt_pad2))
        fmt.Println("rt_pad3", unsafe.Offsetof(r2.rt_pad3))
        fmt.Println("rt_pad4", unsafe.Offsetof(r2.rt_pad4))
        fmt.Println("rt_metric", unsafe.Offsetof(r2.rt_metric))
        fmt.Println("rt_dev", unsafe.Offsetof(r2.rt_dev))
        fmt.Println("rt_mtu", unsafe.Offsetof(r2.rt_mtu))
        fmt.Println("rt_window", unsafe.Offsetof(r2.rt_window))
        fmt.Println("rt_irtt", unsafe.Offsetof(r2.rt_irtt))
}
