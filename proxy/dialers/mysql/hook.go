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

// Package mysql adds a 'cloudsql' network to use when you want to access a
// Cloud SQL Database via the mysql driver found at
// github.com/go-sql-driver/mysql. It also exposes helper functions for
// dialing.
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/GoogleCloudPlatform/cloudsql-proxy/proxy/proxy"
	"github.com/go-sql-driver/mysql"

	"github.com/GoogleCloudPlatform/cloudsql-proxy/internal/observability"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
)

var dbDriverName string

func init() {
	mysql.RegisterDial("cloudsql", proxy.Dial)
	dbDriverName, _ = observability.MakeInstrumentedDBName("mysql")
}

// Dial logs into the specified Cloud SQL Instance using the given user and no
// password. To set more options, consider calling DialCfg instead.
//
// The provided instance should be in the form project-name:region:instance-name.
//
// The returned *sql.DB may be valid even if there's also an error returned
// (e.g. if there was a transient connection error).
func Dial(instance, user string) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Addr = instance
	return DialCfg(cfg)
}

// DialPassword is similar to Dial, but allows you to specify a password.
//
// Note that using a password with the proxy is not necessary as long as the
// user's hostname in the mysql.user table is 'cloudsqlproxy~'. For more
// information, see:
//    https://cloud.google.com/sql/docs/sql-proxy#user
func DialPassword(instance, user, password string) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Addr = instance
	return DialCfg(cfg)
}

// Cfg returns the effective *mysql.Config to represent connectivity to the
// provided instance via the given user and password. The config can be
// modified and passed to DialCfg to connect. If you don't modify the returned
// config before dialing, consider using Dial or DialPassword.
func Cfg(instance, user, password string) *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Addr = instance
	cfg.Net = "cloudsql"
	return cfg
}

// DialCfg opens up a SQL connection to a Cloud SQL Instance specified by the
// provided configuration. It is otherwise the same as Dial.
//
// The cfg.Addr should be the instance's connection string, in the format of:
//	      project-name:region:instance-name.
func DialCfg(cfg *mysql.Config) (db *sql.DB, err error) {
	ctx, _ := tag.New(context.Background(),
		tag.Insert(observability.KeyInstance, cfg.Addr),
		tag.Insert(observability.KeyDBType, "mysql"))

	ctx, span := trace.StartSpan(ctx, "cloudsqlproxy/dialers/mysql/DialCfg")
	startTime := time.Now()
	defer func() {
		ms := []stats.Measurement{observability.MDialLatencyMilliseconds.M(observability.SinceInMilliseconds(startTime)), observability.MDials.M(1)}
		if err != nil {
			ms = append(ms, observability.MErrorDial.M(1))
			span.SetStatus(trace.Status{Code: trace.StatusCodeUnknown, Message: err.Error()})
		}
		stats.Record(ctx, ms...)
		span.End()
	}()

	if cfg.TLSConfig != "" {
		err = errors.New("do not specify TLS when using the Proxy")
		return
	}

	// Copy the config so that we can modify it without feeling bad.
	c := *cfg
	c.Net = "cloudsql"
	dsn := c.FormatDSN()

	db, err = sql.Open(dbDriverName, dsn)
	if err == nil {
		err = db.PingContext(ctx)
	}
	return
}
