package bpf

import "context"

type EventType int

const (
	Chdir EventType = iota
)

type Event struct {
	EventType EventType
	Pid       int
	UPid      int
	Path      string
}

type EventsMonitor interface {
	Load() error
	Listen(ctx context.Context, messageChan chan<- Event) error
	Close()
}
