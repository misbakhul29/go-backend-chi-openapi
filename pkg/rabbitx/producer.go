package rabbitx

import (
	"context"

	"github.com/misbakhul29/backend-framework/pkg/observer"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func Publish(ctx context.Context, conn *amqp.Connection, exchange, routingKey string, body []byte) error {
	if conn == nil || conn.IsClosed() {
		return nil
	}
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	headers := amqp.Table{}
	if observer.Tracer != nil {
		var span trace.Span
		ctx, span = observer.Tracer.Start(ctx, "rabbitmq.publish",
			trace.WithSpanKind(trace.SpanKindProducer),
			trace.WithAttributes(
				attribute.String("messaging.system", "rabbitmq"),
				attribute.String("messaging.destination", exchange),
				attribute.String("messaging.routing_key", routingKey),
			),
		)
		defer span.End()

		carrier := propagation.MapCarrier{}
		observer.Propagator.Inject(ctx, carrier)
		for k, v := range carrier {
			headers[k] = v
		}
	}

	observer.RecordRabbitMQPublished(ctx, exchange)

	return ch.PublishWithContext(ctx,
		exchange,
		routingKey,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Headers:     headers,
			Body:        body,
		},
	)
}
