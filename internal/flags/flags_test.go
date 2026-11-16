package flags

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestApplyKubeAPIRateLimit(t *testing.T) {
	tests := []struct {
		name      string
		qps       float32
		burst     int
		wantQPS   float32
		wantBurst int
	}{
		{name: "defaults keep client-go values", wantQPS: 0, wantBurst: 0},
		{name: "positive qps without burst gets default burst", qps: 100, wantQPS: 100, wantBurst: 10},
		{name: "positive qps with burst", qps: 100, burst: 200, wantQPS: 100, wantBurst: 200},
		{name: "burst without qps", burst: 50, wantQPS: 0, wantBurst: 50},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &Flags{
				RestConfig:   &rest.Config{},
				kubeAPIQPS:   tc.qps,
				kubeAPIBurst: tc.burst,
			}
			f.applyKubeAPIRateLimit()
			if f.RestConfig.QPS != tc.wantQPS {
				t.Errorf("QPS = %v, want %v", f.RestConfig.QPS, tc.wantQPS)
			}
			if f.RestConfig.Burst != tc.wantBurst {
				t.Errorf("Burst = %d, want %d", f.RestConfig.Burst, tc.wantBurst)
			}
		})
	}
}
