// Package lightsail polls burst capacity (CPU credits) of Lightsail instances.
// It runs only when AWS credentials are configured; needs lightsail:GetInstances and lightsail:GetInstanceMetricData.
package lightsail

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	ls "github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/lightsail/types"

	"github.com/thomaskhub/loglantern/internal/config"
	"github.com/thomaskhub/loglantern/internal/record"
)

// API is the part of the Lightsail client used here.
type API interface {
	GetInstances(ctx context.Context, in *ls.GetInstancesInput, opts ...func(*ls.Options)) (*ls.GetInstancesOutput, error)
	GetInstanceMetricData(ctx context.Context, in *ls.GetInstanceMetricDataInput, opts ...func(*ls.Options)) (*ls.GetInstanceMetricDataOutput, error)
}

// Poller reads all regions.
type Poller struct {
	Clients   map[string]API // region → client
	Instances map[string]config.LightsailMapping
	Log       *slog.Logger
	Now       func() time.Time
}

// New builds a poller from config; cfg.LightsailEnabled() must be true.
func New(cfg *config.Config, log *slog.Logger) *Poller {
	l := cfg.Lightsail
	creds := credentials.NewStaticCredentialsProvider(cfg.Secret(l.AccessKeyEnv), cfg.Secret(l.SecretKeyEnv), "")
	p := &Poller{Clients: map[string]API{}, Instances: l.Instances, Log: log, Now: time.Now}
	for _, region := range l.Regions {
		p.Clients[region] = ls.New(ls.Options{Region: region, Credentials: creds, RetryMaxAttempts: 3,
			BaseEndpoint: nilIfEmpty(l.Endpoint)})
	}
	return p
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Poll returns one metric record per mapped instance (unmapped instances are skipped).
func (p *Poller) Poll(ctx context.Context) ([]record.Record, error) {
	var out []record.Record
	now := p.Now()
	for region, c := range p.Clients {
		var token *string
		for {
			res, err := c.GetInstances(ctx, &ls.GetInstancesInput{PageToken: token})
			if err != nil {
				return out, fmt.Errorf("lightsail %s: %w", region, err)
			}
			for _, in := range res.Instances {
				name := aws.ToString(in.Name)
				m, ok := p.Instances[name]
				if !ok {
					continue
				}
				rec := record.Record{Kind: record.KindMetric, TS: now, Env: m.Env, Host: m.Host, Service: "lightsail", Synthetic: true, Values: map[string]float64{}, Texts: map[string]string{}}
				if in.State != nil {
					rec.Texts["lightsail.state"] = aws.ToString(in.State.Name)
				}
				for _, mt := range []struct {
					name types.InstanceMetricName
					unit types.MetricUnit
					key  string
					div  float64
				}{
					{types.InstanceMetricNameBurstCapacityPercentage, types.MetricUnitPercent, "lightsail.burst_pct", 1},
					{types.InstanceMetricNameBurstCapacityTime, types.MetricUnitSeconds, "lightsail.burst_minutes", 60},
				} {
					v, ok, err := p.latest(ctx, c, name, mt.name, mt.unit, now)
					if err != nil {
						p.Log.Warn("lightsail metric", "instance", name, "metric", mt.name, "err", err)
						continue
					}
					if ok {
						rec.Values[mt.key] = v / mt.div
					}
				}
				out = append(out, rec)
			}
			if res.NextPageToken == nil || *res.NextPageToken == "" {
				break
			}
			token = res.NextPageToken
		}
	}
	return out, nil
}

// latest returns the newest 5-minute average of the last 30 minutes.
func (p *Poller) latest(ctx context.Context, c API, inst string, m types.InstanceMetricName, unit types.MetricUnit, now time.Time) (float64, bool, error) {
	res, err := c.GetInstanceMetricData(ctx, &ls.GetInstanceMetricDataInput{
		InstanceName: &inst, MetricName: m, Period: aws.Int32(300), Unit: unit,
		StartTime: aws.Time(now.Add(-30 * time.Minute)), EndTime: aws.Time(now),
		Statistics: []types.MetricStatistic{types.MetricStatisticAverage},
	})
	if err != nil {
		return 0, false, err
	}
	var best *types.MetricDatapoint
	for i, d := range res.MetricData {
		if d.Average != nil && d.Timestamp != nil && (best == nil || d.Timestamp.After(*best.Timestamp)) {
			best = &res.MetricData[i]
		}
	}
	if best == nil {
		return 0, false, nil
	}
	return *best.Average, true, nil
}

// Run polls every interval until ctx ends.
func (p *Poller) Run(ctx context.Context, every time.Duration, emit func(record.Record)) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		recs, err := p.Poll(ctx)
		if err != nil {
			p.Log.Warn("lightsail poll", "err", err)
		}
		for _, r := range recs {
			emit(r)
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}
