//
// tunnel_linux.go
//
// Copyright (c) 2019-2023 Markku Rossi
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
	"ip addr add {{.LocalIP}} peer {{.RemoteIP}} dev {{.Iface}}",
	// "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
	"ip link set dev {{.Iface}} up",
}

var unsetCommands = []string{
	"route delete {{.ServerIP}} {{.GatewayIP}}",
}

type config struct {
	Config
	Iface string
}

// Configure configures the virtual interface according to the
// configuration parameters.
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
