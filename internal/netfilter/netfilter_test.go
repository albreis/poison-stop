package netfilter

import (
	"strings"
	"testing"
)

func TestSelect(t *testing.T) {
	all := []dockerNetwork{
		{ID: "aaaaaaaaaaaa1234", Name: "legado_default", Driver: "bridge"},
		{ID: "bbbbbbbbbbbb1234", Name: "poisonstop-demo_egress", Driver: "bridge"},
		{ID: "cccccccccccc1234", Name: "poisonstop-demo_apps", Driver: "bridge", Internal: true},
		{ID: "dddddddddddd1234", Name: "bridge", Driver: "bridge", Options: map[string]string{"com.docker.network.bridge.name": "docker0"}},
		{ID: "eeeeeeeeeeee1234", Name: "host", Driver: "host"},
		{ID: "ffffffffffff1234", Name: "outra", Driver: "bridge"},
	}
	all[0].IPAM.Config = append(all[0].IPAM.Config, struct {
		Subnet string `json:"Subnet"`
	}{"172.40.0.0/16"})
	all[1].IPAM.Config = append(all[1].IPAM.Config, struct {
		Subnet string `json:"Subnet"`
	}{"10.89.1.0/24"})
	all[3].IPAM.Config = append(all[3].IPAM.Config, struct {
		Subnet string `json:"Subnet"`
	}{"172.17.0.0/16"})
	all[5].IPAM.Config = append(all[5].IPAM.Config, struct {
		Subnet string `json:"Subnet"`
	}{"172.41.0.0/16"})

	got := Select(all, []string{"*"}, []string{"outra"}, "10.89.1.2")
	if len(got) != 2 || got[0].Name != "bridge" || got[0].Bridge != "docker0" || got[1].Bridge != "br-aaaaaaaaaaaa" {
		t.Errorf("seleção errada: %+v", got)
	}
	got = Select(all, []string{"legado_default"}, nil, "10.89.1.2")
	if len(got) != 1 || got[0].Subnet != "172.40.0.0/16" {
		t.Errorf("seleção por nome errada: %+v", got)
	}
}

func TestApplyAndCleanup(t *testing.T) {
	var calls []string
	chains := map[string]bool{}
	run := func(args ...string) error {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case args[2] == "-L":
			if !chains[args[3]] {
				return errFake
			}
		case args[2] == "-N":
			chains[args[3]] = true
		case args[2] == "-C":
			return errFake
		case args[2] == "-D":
			return errFake // nada para apagar
		}
		return nil
	}
	m := NewManager(run)
	rules := Rules([]Network{{Name: "legado", Bridge: "br-aaaa", Subnet: "172.40.0.0/16"}}, "10.89.1.2", 3180, 3443)
	if err := m.Apply(rules); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{
		"-t nat -I PREROUTING 1 -j POISONSTOP-PRE",
		"-t filter -I DOCKER-USER 1 -j POISONSTOP-FWD",
		"-t nat -A POISONSTOP-PRE -d 10.0.0.0/8 -j RETURN",
		"-t nat -A POISONSTOP-PRE -i br-aaaa -p tcp --dport 443 -j DNAT --to-destination 10.89.1.2:3443",
		"-t nat -A POISONSTOP-POST -s 172.40.0.0/16 -d 10.89.1.2 -j ACCEPT",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("faltou: %s", want)
		}
	}
	n := len(calls)
	if err := m.Apply(rules); err != nil || len(calls) != n {
		t.Error("aplicar as mesmas regras de novo não deveria mexer no iptables")
	}
	m.Cleanup()
	if !strings.Contains(strings.Join(calls[n:], "\n"), "-t nat -X POISONSTOP-PRE") {
		t.Error("cleanup deveria apagar as chains")
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "fake" }

var errFake = fakeErr{}
