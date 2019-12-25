//
// tunnel_darwin.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package tun

import (
	"fmt"
	"os/exec"
	"strings"
	"text/template"
)

var setCommands = []string{
	"ifconfig {{.Iface}} {{.LocalIP}} {{.RemoteIP}} up",
	//"ifconfig {{.Iface}} inet6 {{.LocalIP6}} {{.RemoteIP6}} prefixlen 128 up",

	// Add route to the VPN server via current default GW
	//"route add {{.ServerIP}} {{.GatewayIP}}",

	// Default route via VPN
	//"route add 0/1 {{.RemoteIP}}",
	//"route add 128/1 {{.RemoteIP}}",

	//"route add -inet6 -blackhole 0000::/1 {{.RemoteIP6}}",
	//"route add -inet6 -blackhole 8000::/1 {{.RemoteIP6}}",
}

var unsetCommands = []string{
	"route delete {{.ServerIP}} {{.GatewayIP}}",
}

type config struct {
	Config
	Iface string
}

func (t *Tunnel) Configure(cfg Config) error {
	for _, command := range setCommands {
		tmpl := template.Must(template.New("set").Parse(command))

		builder := new(strings.Builder)
		err := tmpl.Execute(builder, config{
			Iface:  t.Name,
			Config: cfg,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Command: %s\n", builder.String())

		args := strings.Split(builder.String(), " ")

		cmd := exec.Command(args[0], args[1:]...)
		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}
