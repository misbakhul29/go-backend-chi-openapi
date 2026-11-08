package observer

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
)

const (
	gormSpanKey  = "gorm:otel_span"
	gormStartKey = "gorm:start_time"
)

type GormTracingPlugin struct{}

func NewGormTracingPlugin() *GormTracingPlugin {
	return &GormTracingPlugin{}
}

func (p *GormTracingPlugin) Name() string {
	return "GormOtelTracing"
}

func (p *GormTracingPlugin) Initialize(db *gorm.DB) error {
	_ = db.Callback().Create().Before("gorm:create").Register("otel:before_create", beforeCallback)
	_ = db.Callback().Create().After("gorm:create").Register("otel:after_create", afterCallback)

	_ = db.Callback().Query().Before("gorm:query").Register("otel:before_query", beforeCallback)
	_ = db.Callback().Query().After("gorm:query").Register("otel:after_query", afterCallback)

	_ = db.Callback().Update().Before("gorm:update").Register("otel:before_update", beforeCallback)
	_ = db.Callback().Update().After("gorm:update").Register("otel:after_update", afterCallback)

	_ = db.Callback().Delete().Before("gorm:delete").Register("otel:before_delete", beforeCallback)
	_ = db.Callback().Delete().After("gorm:delete").Register("otel:after_delete", afterCallback)

	_ = db.Callback().Row().Before("gorm:row").Register("otel:before_row", beforeCallback)
	_ = db.Callback().Row().After("gorm:row").Register("otel:after_row", afterCallback)

	_ = db.Callback().Raw().Before("gorm:raw").Register("otel:before_raw", beforeCallback)
	_ = db.Callback().Raw().After("gorm:raw").Register("otel:after_raw", afterCallback)

	return nil
}

func beforeCallback(db *gorm.DB) {
	if db == nil || db.Statement == nil || Tracer == nil {
		return
	}
	ctx := db.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}

	spanName := "db.query"
	if db.Statement.Table != "" {
		spanName = "db.query " + db.Statement.Table
	}

	ctx, span := Tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.String("db.table", db.Statement.Table),
		),
	)

	db.Set(gormSpanKey, span)
	db.Set(gormStartKey, time.Now())
	db.Statement.Context = ctx
}

func afterCallback(db *gorm.DB) {
	if db == nil || db.Statement == nil {
		return
	}
	val, ok := db.Get(gormSpanKey)
	if !ok {
		return
	}
	span, ok := val.(trace.Span)
	if !ok {
		return
	}
	defer span.End()

	if startVal, ok := db.Get(gormStartKey); ok {
		if startTime, ok := startVal.(time.Time); ok {
			duration := time.Since(startTime).Seconds()
			if dbQueryDurationHist != nil {
				dbQueryDurationHist.Record(db.Statement.Context, duration,
					metric.WithAttributes(attribute.String("db.table", db.Statement.Table)),
				)
			}
		}
	}

	span.SetAttributes(
		attribute.String("db.statement", db.Statement.SQL.String()),
		attribute.Int64("db.rows_affected", db.Statement.RowsAffected),
	)

	if db.Error != nil && db.Error != gorm.ErrRecordNotFound {
		span.RecordError(db.Error)
		span.SetStatus(codes.Error, db.Error.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

