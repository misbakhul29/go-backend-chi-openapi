package rabbitx

import (
	"fmt"
	"strings"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	amqp "github.com/rabbitmq/amqp091-go"
)

type TopologyConfig struct {
	Prefix         string
	EventsExchange string
	JobsExchange   string
	NotifyExchange string
	DLXExchange    string
	DeadQueue      string
}

func NewTopologyConfig(prefix string) TopologyConfig {
	p := strings.ToLower(strings.TrimSpace(prefix))
	p = strings.ReplaceAll(p, " ", "-")
	p = strings.Trim(p, ".")
	for strings.Contains(p, "..") {
		p = strings.ReplaceAll(p, "..", ".")
	}
	if p == "" {
		p = "app"
	}
	return TopologyConfig{
		Prefix:         p,
		EventsExchange: fmt.Sprintf("%s.events", p),
		JobsExchange:   fmt.Sprintf("%s.jobs", p),
		NotifyExchange: fmt.Sprintf("%s.notifications", p),
		DLXExchange:    fmt.Sprintf("%s.dlx", p),
		DeadQueue:      fmt.Sprintf("%s.dead", p),
	}
}

func DefaultExchangeNames(prefixes ...string) TopologyConfig {
	if len(prefixes) > 0 && strings.TrimSpace(prefixes[0]) != "" {
		return NewTopologyConfig(prefixes[0])
	}
	if config.Cfg != nil && strings.TrimSpace(config.Cfg.RabbitMQ.ExchangePrefix) != "" {
		return NewTopologyConfig(config.Cfg.RabbitMQ.ExchangePrefix)
	}
	return NewTopologyConfig("app")
}

func InitRabbit(cfg config.RabbitMQ) (*amqp.Connection, error) {
	conn, err := amqp.Dial(cfg.RabbitUrl())
	if err != nil {
		observer.Log.Error("failed to connect to RabbitMQ", "error", err)
		return nil, err
	}

	observer.Log.Info("RabbitMQ connection established successfully")

	prefix := cfg.ExchangePrefix
	if prefix == "" && config.Cfg != nil {
		prefix = config.Cfg.RabbitMQ.ExchangePrefix
	}

	if err := EnsureTopology(conn, prefix); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to setup topology: %w", err)
	}

	return conn, nil
}

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

func EnsureTopology(conn *amqp.Connection, prefixes ...string) error {
	topo := DefaultExchangeNames(prefixes...)

	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	exchanges := []struct {
		name string
		kind string
	}{
		{topo.EventsExchange, "topic"},
		{topo.JobsExchange, "direct"},
		{topo.NotifyExchange, "topic"},
		{topo.DLXExchange, "topic"},
	}

	for _, ex := range exchanges {
		err = ch.ExchangeDeclare(
			ex.name,
			ex.kind,
			true,
			false,
			false,
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("declare exchange %s: %w", ex.name, err)
		}
	}

	_, err = ch.QueueDeclare(
		topo.DeadQueue,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("declare %s queue: %w", topo.DeadQueue, err)
	}

	err = ch.QueueBind(
		topo.DeadQueue,
		"#",
		topo.DLXExchange,
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("bind %s queue: %w", topo.DeadQueue, err)
	}

	return nil
}

func DeclareQueue(ch *amqp.Channel, name, boundToExchange, routingKey string, withDLQ bool, dlxExchange ...string) error {
	dlx := DefaultExchangeNames().DLXExchange
	if len(dlxExchange) > 0 && strings.TrimSpace(dlxExchange[0]) != "" {
		dlx = strings.TrimSpace(dlxExchange[0])
	}

	var args amqp.Table
	if withDLQ {
		args = amqp.Table{
			"x-dead-letter-exchange":    dlx,
			"x-dead-letter-routing-key": name + ".dead",
		}
	}

	_, err := ch.QueueDeclare(
		name,
		true,
		false,
		false,
		false,
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
			true,
			false,
			false,
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("declare DLQ %s: %w", dlqName, err)
		}

		err = ch.QueueBind(
			dlqName,
			dlqName,
			dlx,
			false,
			nil,
		)
		if err != nil {
			return fmt.Errorf("bind DLQ %s to DLX: %w", dlqName, err)
		}

		retryQueueName := name + ".retry"
		_, err = ch.QueueDeclare(
			retryQueueName,
			true,
			false,
			false,
			false,
			amqp.Table{
				"x-dead-letter-exchange":    "",
				"x-dead-letter-routing-key": name,
				"x-message-ttl":             int32(5000),
			},
		)
		if err != nil {
			return fmt.Errorf("declare retry queue %s: %w", retryQueueName, err)
		}
	}

	return nil
}
