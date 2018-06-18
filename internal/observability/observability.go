// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observability

import (
	"database/sql/driver"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"

	"github.com/basvanbeek/ocsql"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"github.com/DataDog/opencensus-go-exporter-datadog"
	xray "github.com/census-ecosystem/opencensus-go-exporter-aws"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"go.opencensus.io/exporter/jaeger"
	"go.opencensus.io/exporter/prometheus"
	"go.opencensus.io/exporter/zipkin"
)

const (
	unitDimensionless = "1"
	unitMilliseconds  = "ms"
)

var (
	// db_type can either be "mysql" or "postgresql"
	KeyDBType, _   = tag.NewKey("db_type")
	KeyInstance, _ = tag.NewKey("instance")
	KeyMethod, _   = tag.NewKey("method")
	KeyPhase, _    = tag.NewKey("phase")
	KeyReason, _   = tag.NewKey("reason")
	KeyType, _     = tag.NewKey("type")
	KeyCertType, _ = tag.NewKey("cert_type")
	// Connections can either be: "new", "reused"
	KeyConnectionState, _ = tag.NewKey("conn_state")
	// throttled can either be: "true" or "false"(implicit absence)
	KeyThrottled, _ = tag.NewKey("throttled")

	// status is indicative of any one-of of any enumeration e.g "error" vs "success"
	KeyStatus, _ = tag.NewKey("status")
)

// Measures
var (
	MErrors = stats.Int64("cloudsqlproxy/errors", "The number of errors encountered", unitDimensionless)

	MCertsAdded = stats.Int64("cloudsqlproxy/certs_added", "The number of newly added certificates", unitDimensionless)

	MInboundConnections  = stats.Int64("cloudsqlproxy/connections_in", "The number of inbound connections from clients to the proxy", unitDimensionless)
	MOutboundConnections = stats.Int64("cloudsqlproxy/connections_out", "The number of outbound connections to the proxy to CloudSQL instances", unitDimensionless)

	MLatencyMs = stats.Float64("cloudsqlproxy/latency_cert_refresh", "The overall latency for refreshing certificates", unitMilliseconds)

	MCertRefreshLatencyMs = stats.Float64("cloudsqlproxy/latency_cert_refresh", "The overall latency for refreshing certificates", unitMilliseconds)
)

// Distributions
var (
	// Copied from https://github.com/census-instrumentation/opencensus-go/blob/ff7de98412e5c010eb978f11056f90c00561637f/plugin/ocgrpc/stats_common.go#L54
	defaultBytesDistribution = view.Distribution(0, 1024, 2048, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 268435456, 1073741824, 4294967296)
	// Copied from https://github.com/census-instrumentation/opencensus-go/blob/ff7de98412e5c010eb978f11056f90c00561637f/plugin/ocgrpc/stats_common.go#L55
	defaultMillisecondsDistribution = view.Distribution(0, 0.01, 0.05, 0.1, 0.3, 0.6, 0.8, 1, 2, 3, 4, 5, 6, 8, 10, 13, 16, 20, 25, 30, 40, 50, 65, 80, 100, 130, 160, 200, 250, 300, 400, 500, 650, 800, 1000, 2000, 5000, 10000, 20000, 50000, 100000)
)

// Views
var allViews = []*view.View{
	{
		Name:        "cloudsqlproxy/connections_in",
		Measure:     MInboundConnections,
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{KeyInstance, KeyDBType},
		Description: "The number of dials to an instance server",
	},
	{
		Name:        "cloudsqlproxy/connections_out",
		Measure:     MOutboundConnections,
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{KeyInstance, KeyDBType},
		Description: "The number of dials to an instance server",
	},
	{
		Name:        "cloudsqlproxy/certs_added",
		Measure:     MCertsAdded,
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{KeyInstance, KeyType},
		Description: "The number of newly added certificates",
	},
	{
		Name:        "cloudsqlproxy/errors",
		Measure:     MErrors,
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{KeyInstance, KeyType, KeyCertType, KeyPhase, KeyReason},
		Description: "The number of errors encountered",
	},
	{
		Name:        "cloudsqlproxy/latency",
		Measure:     MLatencyMs,
		Aggregation: defaultMillisecondsDistribution,
		TagKeys:     []tag.Key{KeyInstance, KeyDBType, KeyMethod},
		Description: "The latency encountered for methods on the proxy",
	},
	{
		Name:        "cloudsqlproxy/cert_refresh_latency",
		Measure:     MCertRefreshLatencyMs,
		Aggregation: defaultMillisecondsDistribution,
		TagKeys:     []tag.Key{KeyInstance, KeyDBType, KeyMethod},
		Description: "The latency encountered while fetching certificates",
	},
}

func ToMilliseconds(d time.Duration) float64 {
	// Durations are in nanoseconds so convert them to milliseconds by 1e6 division
	return float64(d.Nanoseconds()) / 1e6
}

func SinceInMilliseconds(startTime time.Time) float64 {
	return ToMilliseconds(time.Since(startTime))
}

func RegisterAllViews() error {
	return view.Register(allViews...)
}

func InstrumentedTransportWithOpenCensus(rt http.RoundTripper) http.RoundTripper {
	return &ochttp.Transport{Base: rt}
}

func parseAWSXrayDefinition(keyValues []string) (*Definition, error) {
	def := &Definition{EnableTracing: true}
	return def, nil
}

func parseZipkinDefinition(keyValues []string) (*Definition, error) {
	localEndpointURI := "192.168.1.5:5454"
	reporterURI := "http://localhost:9411/api/v2/spans"
	serviceName := "server"

	for _, keyValue := range keyValues {
		splits := strings.Split(keyValue, keyValueSeparator)

		switch strings.ToLower(splits[0]) {
		case "local":
			if len(splits) > 0 {
				localEndpointURI = splits[1]
			}
		case "reporter":
			if len(splits) > 0 {
				reporterURI = splits[1]
			}
		case "service-name":
			if len(splits) > 1 {
				serviceName = splits[1]
			}
		}
	}

	def := &Definition{
		EnableTracing:    true,
		LocalEndpointURI: localEndpointURI,
		ReporterURI:      reporterURI,
		ServiceName:      serviceName,
	}
	return def, nil
}

func parseJaegerDefinition(keyValues []string) (*Definition, error) {
	agentEndpointURI := "localhost:6831"
	collectorEndpointURI := "http://localhost:9411"
	serviceName := ""

	for _, kv := range keyValues {
		kvSplit := strings.Split(kv, "=")

		switch strings.ToLower(kvSplit[0]) {
		case "collector":
			if len(kvSplit) > 0 {
				collectorEndpointURI = kvSplit[1]
			}
		case "agent":
			if len(kvSplit) > 0 {
				agentEndpointURI = kvSplit[1]
			}
		case "service-name":
			if len(kvSplit) > 1 {
				serviceName = kvSplit[1]
			}
		}
	}

	def := &Definition{
		AgentEndpointURI:     agentEndpointURI,
		CollectorEndpointURI: collectorEndpointURI,
		ServiceName:          serviceName,
	}
	return def, nil
}

func createJaegerExporter(def *Definition) (flusher, error) {
	if def == nil {
		return blankFlusher, nil
	}

	je, err := jaeger.NewExporter(jaeger.Options{
		ServiceName:   def.ServiceName,
		AgentEndpoint: def.AgentEndpointURI,
		Endpoint:      def.CollectorEndpointURI,
	})
	if err != nil {
		return blankFlusher, err
	}
	return flusher(func() error { je.Flush(); return nil }), nil
}

func createZipkinExporter(def *Definition) error {
	if def == nil {
		return nil
	}

	localEndpoint, err := openzipkin.NewEndpoint(def.ServiceName, def.LocalEndpointURI)
	if err != nil {
		return fmt.Errorf("Failed to create Zipkin localEndpoint with URI %q error: %v", def.LocalEndpointURI, err)
	}

	reporter := zipkinHTTP.NewReporter(def.ReporterURI)
	ze := zipkin.NewExporter(reporter, localEndpoint)
	trace.RegisterExporter(ze)
	return nil
}

func parseDataDogDefinition(keyValues []string) (*Definition, error) {
	def := new(Definition)
	for _, kv := range keyValues {
		splits := strings.Split(kv, keyValueSeparator)

		switch splits[0] {
		case "monitoring":
			def.EnableMonitoring = len(splits) > 1 && splits[1] == "true"
		case "tracing":
			def.EnableTracing = len(splits) > 1 && splits[1] == "true"
		case "service":
			if len(splits) > 1 {
				def.ServiceName = splits[1]
			}
		case "namespace":
			if len(splits) > 1 {
				def.Namespace = splits[1]
			}
		case "metric-prefix":
			if len(splits) > 1 {
				def.MetricPrefix = splits[1]
			}
		case "tags":
			if len(splits) > 1 {
				def.DataDogTags = strings.Split(splits[1], "+")
			}
		case "stats_addr":
			if len(splits) > 1 {
				def.StatsServerURI = splits[1]
			}
		case "traces_addr":
			if len(splits) > 1 {
				def.TracesServerURI = splits[1]
			}
		}
	}
	return def, nil
}

func createDataDogExporter(def *Definition) (flusher, error) {
	if def == nil {
		return blankFlusher, nil
	}
	opts := datadog.Options{
		Namespace: def.Namespace,
		Service:   def.ServiceName,
		Tags:      def.DataDogTags,
		TraceAddr: def.TracesServerURI,
		StatsAddr: def.StatsServerURI,
	}
	dex := datadog.NewExporter(opts)
	if def.EnableTracing {
		trace.RegisterExporter(dex)
	}
	if def.EnableMonitoring {
		view.RegisterExporter(dex)
	}
	return flusher(func() error { dex.Stop(); return nil }), nil
}

func createAWSXrayExporter(def *Definition) error {
	xe, err := xray.NewExporter(xray.WithVersion("latest"))
	if err != nil {
		return err
	}
	trace.RegisterExporter(xe)
	return nil
}

type flusher func() error

func parseStackdriverDefinition(projectIDs, keyValues []string) (*Definition, error) {
	var metricPrefix string
	var enableTracing, enableMonitoring bool

	for _, kv := range keyValues {
		splits := strings.Split(kv, keyValueSeparator)

		switch splits[0] {
		case "monitoring":
			enableMonitoring = len(splits) > 1 && splits[1] == "true"
		case "tracing":
			enableTracing = len(splits) > 1 && splits[1] == "true"
		case "metric-prefix":
			if len(splits) > 1 {
				metricPrefix = splits[1]
			}
		}
	}

	def := &Definition{
		ProjectIDs:       projectIDs,
		EnableTracing:    enableTracing,
		EnableMonitoring: enableMonitoring,
		MetricPrefix:     metricPrefix,
	}
	return def, nil
}

func createStackdriverExporter(def *Definition) (flusher, error) {
	if def == nil {
		return blankFlusher, nil
	}
	ok := def.EnableTracing || def.EnableMonitoring
	if !ok {
		return blankFlusher, nil
	}
	flushers := make([]flusher, 0, len(def.ProjectIDs))
	// 2. Create the Stackdriver exporters
	for _, projectID := range def.ProjectIDs {
		// 2a. Create the Stackdriver Tracing exporters for each project
		sd, err := stackdriver.NewExporter(stackdriver.Options{
			ProjectID:    projectID,
			MetricPrefix: def.MetricPrefix,
		})
		if err != nil {
			return blankFlusher, fmt.Errorf("Stackdriver.NewExporter(%q): %v", projectID, err)
		}
		if def.EnableTracing {
			trace.RegisterExporter(sd)
		}
		if def.EnableMonitoring {
			view.RegisterExporter(sd)
		}
		flushers = append(flushers, flusher(func() error { sd.Flush(); return nil }))
	}
	return combineFlushers(flushers), nil
}

func combineFlushers(flushers []flusher) flusher {
	return func() error {
		for _, fn := range flushers {
			if fn != nil {
				if err := fn(); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

const defaultPrometheusPort = int(9889)

func parsePrometheusDefinition(keyValues []string) (*Definition, error) {
	// prometheus:namespace=foo:port=9889
	var namespace string
	port := defaultPrometheusPort
	for _, kv := range keyValues {
		splits := strings.Split(kv, keyValueSeparator)

		switch splits[0] {
		case "namespace":
			if len(splits) > 1 {
				namespace = splits[1]
			} else {
				return nil, fmt.Errorf("Prometheus: port expected to be specified")
			}
		case "port":
			if len(splits) > 1 {
				i64, err := strconv.ParseInt(splits[1], 10, 32)
				if err != nil {
					return nil, err
				}
				port = int(i64)
			} else {
				return nil, fmt.Errorf("Prometheus: port expected to be specified")
			}
		}
	}

	def := &Definition{
		Namespace:        namespace,
		Port:             port,
		EnableMonitoring: true,
	}
	return def, nil
}

func createPrometheusExporter(def *Definition) error {
	if def == nil {
		return nil
	}
	pe, err := prometheus.NewExporter(prometheus.Options{
		Namespace: def.Namespace,
	})
	if err != nil {
		return err
	}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", pe)
		addr := fmt.Sprintf(":%d", def.Port)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Prometheus: failed to start server: %v", err)
		}
	}()
	return nil
}

const (
	samplingRateSeparator = ";"
	exportersSeparator    = ","
	configSeparator       = ":"
	keyValueSeparator     = "="
)

func parseSamplingRate(str string) (float64, error) {
	return strconv.ParseFloat(str, 64)
}

type Flusher interface {
	Flush() error
}

var _ Flusher = (*flusher)(nil)

func (f flusher) Flush() error {
	if f == nil {
		return nil
	}
	return f()
}

var blankFlusher = flusher(func() error { return nil })

type Config struct {
	SamplingRate func() float64
	AWSXray      *Definition
	DataDog      *Definition
	Jaeger       *Definition
	Prometheus   *Definition
	Stackdriver  *Definition
	Zipkin       *Definition
}

type Definition struct {
	MetricPrefix     string
	Port             int
	ServiceName      string
	Namespace        string
	ProjectIDs       []string
	EnableTracing    bool
	EnableMonitoring bool

	// These fields are useful only for Zipkin
	LocalEndpointURI string
	ReporterURI      string

	// These fields are only useful for DataDog
	StatsServerURI  string
	TracesServerURI string
	DataDogTags     []string

	// These fields are only useful for Jaeger
	AgentEndpointURI     string
	CollectorEndpointURI string
}

func ParseConfig(strConfig string, projectIDs []string) (*Config, error) {
	strConfig = strings.TrimSpace(strConfig)
	if strConfig == "" {
		return nil, nil
	}
	var err error
	var samplingRate func() float64
	if i := strings.Index(strConfig, samplingRateSeparator); i >= 0 {
		var rate float64
		rate, err = parseSamplingRate(strConfig[:i])
		if err != nil {
			return nil, fmt.Errorf("parseSamplingRate: %v", err)
		}
		strConfig = strConfig[i+1:]
		samplingRate = func() float64 { return rate }
	}
	cfg := &Config{SamplingRate: samplingRate}

	// Now split the rest of the config by the exporters separator
	exporterConfigs := strings.Split(strConfig, exportersSeparator)
	// Expecting content in the form:
	// stackdriver:tracing=true:monitoring=true:metric-prefix=flux,jaeger

	for _, config := range exporterConfigs {
		cfgSplit := strings.Split(config, configSeparator)
		var keyValues []string
		if len(cfgSplit) > 1 {
			keyValues = cfgSplit[1:]
		}
		switch strings.ToLower(cfgSplit[0]) {
		case "datadog":
			def, err := parseDataDogDefinition(keyValues)
			if err != nil {
				return nil, err
			}
			cfg.DataDog = def

		case "jaeger":
			def, err := parseJaegerDefinition(keyValues)
			if err != nil {
				return nil, err
			}
			cfg.Jaeger = def

		case "prometheus":
			def, err := parsePrometheusDefinition(keyValues)
			if err != nil {
				return nil, fmt.Errorf("Prometheus: %v", err)
			}
			cfg.Prometheus = def

		case "stackdriver":
			def, err := parseStackdriverDefinition(projectIDs, keyValues)
			if err != nil {
				return nil, fmt.Errorf("Stackdriver: %v", err)
			}
			cfg.Stackdriver = def

		case "xray":
			def, err := parseAWSXrayDefinition(keyValues)
			if err != nil {
				return nil, err
			}
			cfg.AWSXray = def

		case "zipkin":
			def, err := parseZipkinDefinition(keyValues)
			if err != nil {
				return nil, err
			}
			cfg.Zipkin = def
		}
	}
	return cfg, nil
}

func ParseAndEnableObservabilityWithOpenCensus(strConfig string, projectIDs []string) (doFlush Flusher, ok bool, err error) {
	cfg, err := ParseConfig(strConfig, projectIDs)
	if err != nil {
		return blankFlusher, false, nil
	}
	return EnableObservabilityWithOpenCensus(cfg)
}

func EnableObservabilityWithOpenCensus(cfg *Config) (doFlush Flusher, ok bool, err error) {
	if cfg == nil {
		return blankFlusher, false, nil
	}

	var samplingRate float64
	var userDefinedSamplingRate bool
	if cfg.SamplingRate != nil {
		samplingRate = cfg.SamplingRate()
		userDefinedSamplingRate = true
	}

	if userDefinedSamplingRate {
		switch {
		case samplingRate <= 0.0:
			trace.ApplyConfig(trace.Config{DefaultSampler: trace.NeverSample()})
		case samplingRate >= 1.0:
			trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
		default:
			trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(samplingRate)})
		}
	}

	defsMap := map[string]*Definition{
		"jaeger":      cfg.Jaeger,
		"xray":        cfg.AWSXray,
		"stackdriver": cfg.Stackdriver,
		"zipkin":      cfg.Zipkin,
		"datadog":     cfg.DataDog,
		"proemtheus":  cfg.Prometheus,
	}

	flushers := make([]flusher, 0, len(defsMap))
	for name, def := range defsMap {
		if def == nil { // Unset exporter
			continue
		}
		switch strings.ToLower(name) {
		case "datadog":
			if flusherFn, err := createDataDogExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("DataDog: %v", err)
			} else {
				flushers = append(flushers, flusherFn)
			}
		case "jaeger":
			if flusherFn, err := createJaegerExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("Jaeger: %v", err)
			} else {
				flushers = append(flushers, flusherFn)
			}
		case "prometheus":
			if err := createPrometheusExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("Prometheus: %v", err)
			}
		case "stackdriver":
			if flusherFn, err := createStackdriverExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("Stackdriver: %v", err)
			} else {
				flushers = append(flushers, flusherFn)
			}
		case "xray":
			if err := createAWSXrayExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("AWS X-Ray: %v", err)
			}
		case "zipkin":
			if err := createZipkinExporter(def); err != nil {
				return blankFlusher, false, fmt.Errorf("Zipkin: %v", err)
			}
		}
	}

	// 1a. Register all the views
	if err := RegisterAllViews(); err != nil {
		return blankFlusher, false, fmt.Errorf("RegisterAllViews: %v", err)
	}
	// 1b. Register all the ochttp views
	httpViews := append(ochttp.DefaultServerViews, ochttp.DefaultClientViews...)
	if err := view.Register(httpViews...); err != nil {
		return blankFlusher, false, fmt.Errorf("OCHTTP views: %v", err)
	}
	// 1c. Register all the grcp views
	grpcViews := append(ocgrpc.DefaultServerViews, ocgrpc.DefaultClientViews...)
	if err := view.Register(grpcViews...); err != nil {
		return blankFlusher, false, fmt.Errorf("OCgRPC views: %v", err)
	}

	return combineFlushers(flushers), true, nil
}

func InstrumentDriver(db driver.Driver) driver.Driver {
	return ocsql.Wrap(db)
}

var defaultOCSQLOptions = []ocsql.TraceOption{
	ocsql.WithAllTraceOptions(),
}

func MakeInstrumentedDBName(originalDBName string, options ...ocsql.TraceOption) (string, error) {
	if len(options) == 0 {
		options = defaultOCSQLOptions
	}
	newDBName, err := ocsql.Register(originalDBName, options...)
	if err != nil {
		// The goal here is that if we fail at all, we should return the original DBName
		return originalDBName, err
	}
	return newDBName, nil
}
