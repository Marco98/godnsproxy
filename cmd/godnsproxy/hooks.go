package main

import (
	"sync"

	"github.com/miekg/dns"
)

type Hook interface {
	Hook(resp *dns.Msg)
	Daemon()
}

var hooks []Hook

func runHookDaemons() {
	for _, v := range hooks {
		go v.Daemon()
	}
}

func runHooks(resp *dns.Msg) {
	wg := new(sync.WaitGroup)
	for _, v := range hooks {
		wg.Add(1)
		go func(v Hook, resp *dns.Msg) {
			defer wg.Done()
			v.Hook(resp)
		}(v, resp)
	}
	wg.Wait()
}
