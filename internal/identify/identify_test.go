package identify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentifyDocker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`[
			{"Names":["/demo-app-1"],"Labels":{"poisonstop.service":"loja","com.docker.compose.service":"app"},
			 "NetworkSettings":{"Networks":{"demo_apps":{"IPAddress":"172.30.0.10"}}}},
			{"Names":["/demo-worker-1"],"Labels":{"com.docker.compose.service":"worker","com.docker.compose.project":"meuchefe"},
			 "NetworkSettings":{"Networks":{"demo_apps":{"IPAddress":"172.30.0.11"}}}}
		]`))
	}))
	defer srv.Close()

	id := New(srv.URL, map[string]string{"172.30.0.99": "fixo"})
	for ip, want := range map[string]string{
		"172.30.0.10": "loja",
		"172.30.0.11": "meuchefe/worker",
		"172.30.0.99": "fixo",
		"172.30.0.50": "ip:172.30.0.50",
	} {
		if got := id.Identify(ip); got != want {
			t.Errorf("Identify(%s) = %q, quer %q", ip, got, want)
		}
	}
}
