package rabbitx

import (
	"fmt"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	amqp "github.com/rabbitmq/amqp091-go"
)

// InitRabbit initializes a RabbitMQ connection.
func InitRabbit(cfg config.RabbitMQ) (*amqp.Connection, error) {
	conn, err := amqp.Dial(cfg.RabbitUrl())
	if err != nil {
		observer.Log.Error("failed to connect to RabbitMQ", "error", err)
		return nil, err
	}

	observer.Log.Info("RabbitMQ connection established successfully")

	if err := EnsureTopology(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to setup topology: %w", err)
	}

	return conn, nil
}

// Ping checks RabbitMQ connection health by opening a temporary channel.
func Ping(conn *amqp.Connection) error {
	if conn == nil || conn.IsClosed() {
		return fmt.Errorf("rabbitmq connection is closed")
	}

	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("failed to open verification channel: %w", err)
	}
	defer ch.Close()

	return nil
}

// EnsureTopology declares exchanges and the default DLX/DLQ.
func EnsureTopology(conn *amqp.Connection) error {
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	// 1. Declare Main Exchanges
	exchanges := []struct {
		name string
		kind string
	}{
		{"hris.events", "topic"},
		{"hris.jobs", "direct"},
		{"hris.notifications", "topic"},
		{"hris.dlx", "topic"}, // dead letter exchange
	}

	for _, ex := range exchanges {
		err = ch.ExchangeDeclare(
			ex.name,
			ex.kind,
			true,  // durable
			false, // auto-delete
			false, // internal
			false, // no-wait
			nil,   // arguments
		)
		if err != nil {
			return fmt.Errorf("declare exchange %s: %w", ex.name, err)
		}
	}

	// 2. Declare default hris.dead queue and bind to DLX
	_, err = ch.QueueDeclare(
		"hris.dead",
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("declare hris.dead queue: %w", err)
	}

	err = ch.QueueBind(
		"hris.dead",
		"#", // wildcard for topic exchange hris.dlx
		"hris.dlx",
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("bind hris.dead queue: %w", err)
	}

	return nil
}

// DeclareQueue declares a queue, binds it to an exchange, and optionally configures its DLQ.
func DeclareQueue(ch *amqp.Channel, name, boundToExchange, routingKey string, withDLQ bool) error {
	var args amqp.Table
	if withDLQ {
		args = amqp.Table{
			"x-dead-letter-exchange":    "hris.dlx",
			"x-dead-letter-routing-key": name + ".dead",
		}
	}

	_, err := ch.QueueDeclare(
		name,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		args,
	)
	if err != nil {
		return fmt.Errorf("declare queue %s: %w", name, err)
	}

	if boundToExchange != "" {
		err = ch.QueueBind(
			name,
			routingKey,
			boundToExchange,
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("bind queue %s to %s with %s: %w", name, boundToExchange, routingKey, err)
		}
	}

	if withDLQ {
		dlqName := name + ".dead"
		_, err = ch.QueueDeclare(
			dlqName,
			true,  // durable
			false, // auto-delete
			false, // exclusive
			false, // no-wait
			nil,
		)
		if err != nil {
			return fmt.Errorf("declare DLQ %s: %w", dlqName, err)
		}

		err = ch.QueueBind(
			dlqName,
			dlqName,
			"hris.dlx",
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("bind DLQ %s to DLX: %w", dlqName, err)
		}

		// Declare a retry queue with TTL that dead-letters back to the original queue
		retryQueueName := name + ".retry"
		_, err = ch.QueueDeclare(
			retryQueueName,
			true,  // durable
			false, // auto-delete
			false, // exclusive
			false, // no-wait
			amqp.Table{
				"x-dead-letter-exchange":    "",
				"x-dead-letter-routing-key": name,
				"x-message-ttl":             int32(5000), // 5 seconds retry delay
			},
		)
		if err != nil {
			return fmt.Errorf("declare retry queue %s: %w", retryQueueName, err)
		}
	}

	return nil
}
