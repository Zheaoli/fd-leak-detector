package main

import (
	"context"

	"fd-leak-detector/internal/bpf"
	"fd-leak-detector/internal/bpf/chdir"
	"fd-leak-detector/internal/detector"
)

func main() {
	ctx := context.Background()
	defer ctx.Done()

	eventChan := make(chan bpf.Event, 100000)
	monitor := chdir.NewEventMonitor()
	if err := monitor.Load(); err != nil {
		panic(err)
	}
	go monitor.Listen(ctx, eventChan)

	detector.Detector(ctx, eventChan)
}
