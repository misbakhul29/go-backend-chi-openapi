package rabbitx

import (
	"context"

	amqp "github.com/rabbitmq/amqp091-go"
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

	return ch.PublishWithContext(ctx,
		exchange,
		routingKey,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
}
