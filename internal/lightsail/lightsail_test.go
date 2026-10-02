package lightsail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ls "github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/lightsail/types"

	"github.com/thomkin/loglantern/internal/config"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type fake struct {
	pages   [][]string
	calls   int
	failPct bool
}

func (f *fake) GetInstances(_ context.Context, in *ls.GetInstancesInput, _ ...func(*ls.Options)) (*ls.GetInstancesOutput, error) {
	f.calls++
	i := 0
	if in.PageToken != nil {
		i = 1
	}
	out := &ls.GetInstancesOutput{}
	for _, n := range f.pages[i] {
		out.Instances = append(out.Instances, types.Instance{Name: aws.String(n), State: &types.InstanceState{Name: aws.String("running")}})
	}
	if i+1 < len(f.pages) {
		out.NextPageToken = aws.String("p2")
	}
	return out, nil
}

func (f *fake) GetInstanceMetricData(_ context.Context, in *ls.GetInstanceMetricDataInput, _ ...func(*ls.Options)) (*ls.GetInstanceMetricDataOutput, error) {
	f.calls++
	if in.MetricName == types.InstanceMetricNameBurstCapacityPercentage {
		if f.failPct {
			return nil, errors.New("throttled")
		}
		return &ls.GetInstanceMetricDataOutput{MetricData: []types.MetricDatapoint{
			{Average: aws.Float64(40), Timestamp: aws.Time(now.Add(-10 * time.Minute))},
			{Average: aws.Float64(35), Timestamp: aws.Time(now.Add(-5 * time.Minute))},
		}}, nil
	}
	return &ls.GetInstanceMetricDataOutput{MetricData: []types.MetricDatapoint{{Average: aws.Float64(3600), Timestamp: aws.Time(now.Add(-5 * time.Minute))}}}, nil
}

func TestPoll(t *testing.T) {
	f := &fake{pages: [][]string{{"vm-a", "other"}, {"vm-b"}}}
	p := &Poller{Clients: map[string]API{"eu-central-1": f}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
		Instances: map[string]config.LightsailMapping{"vm-a": {Env: "uat", Host: "api1"}, "vm-b": {Env: "prod", Host: "db1"}}}
	recs, err := p.Poll(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("W1 pages + mapping: %v %+v", err, recs)
	}
	r := recs[0]
	if r.Env != "uat" || r.Host != "api1" || r.Values["lightsail.burst_pct"] != 35 || r.Values["lightsail.burst_minutes"] != 60 || r.Texts["lightsail.state"] != "running" || !r.Synthetic {
		t.Fatalf("W2 newest point, minutes: %+v", r)
	}
	if f.calls != 2+2*2 {
		t.Fatalf("W3 calls per poll: %d", f.calls)
	}
	f.failPct = true
	recs, _ = p.Poll(context.Background())
	if _, ok := recs[0].Values["lightsail.burst_pct"]; ok || recs[0].Values["lightsail.burst_minutes"] != 60 {
		t.Fatalf("W4 one metric failing keeps the other: %+v", recs[0])
	}
}

func TestNewNeedsNoNetwork(t *testing.T) {
	cfg := &config.Config{Lightsail: &config.Lightsail{Regions: []string{"eu-central-1", "ap-south-1"}, AccessKeyEnv: "A", SecretKeyEnv: "S"},
		Secrets: map[string]string{"A": "AKIA", "S": "s"}}
	if p := New(cfg, nil); len(p.Clients) != 2 {
		t.Fatal("clients per region")
	}
}
