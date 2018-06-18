// Copyright 2015 Google Inc. All Rights Reserved.
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

package mysql_test

import (
	"context"
	"log"
	"time"

	"github.com/GoogleCloudPlatform/cloudsql-proxy/internal/observability"
	"github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/dialers/mysql"

	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
)

// ExampleCfg shows how to use Cloud SQL Proxy dialer if you must update some
// settings normally passed in the DSN such as the DBName or timeouts.
func ExampleCfg() {
	cfg := mysql.Cfg("census-demos:us-central1:census-demos-mysql", "root", "")
	cfg.DBName = "mysql"
	cfg.ParseTime = true
	view.SetReportingPeriod(200 * time.Millisecond)
	flusher, _, err := observability.EnableObservabilityWithOpenCensus(&observability.Config{
		SamplingRate: func() float64 { return 1.00 },
		Stackdriver: &observability.Definition{
			ProjectIDs:       []string{"census-demos"},
			EnableTracing:    true,
			EnableMonitoring: true,
			MetricPrefix:     "cloudsql_tests",
		},
	})
	if err != nil {
		log.Fatalf("Failed to enable observability with OpenCensus: %v", err)
	}
	defer flusher.Flush()

	const timeout = 10 * time.Second
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout

	db, err := mysql.DialCfg(cfg)
	if err != nil {
		log.Fatalf("Couldn't dial: %v", err)
	}
	// Close db after this method exits since we don't need it for the
	// connection pooling.
	defer db.Close()

	ctx, span := trace.StartSpan(context.Background(), "ExampleCfg")
	defer span.End()

	var now time.Time
	for i := 0; i < 2; i++ {
		log.Println(db.QueryRowContext(ctx, "SELECT NOW()").Scan(&now))
		log.Println(now)
	}
}
