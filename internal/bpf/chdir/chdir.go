package chdir

import (
	"context"
	"errors"
	"unsafe"

	"fd-leak-detector/internal/bpf"
	"fd-leak-detector/internal/utils"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf ../../../bpf/chdir.c -- -I../../../bpf/headers

type EventMonitor struct {
	messageChan chan bpf.Event
	objects     bpfObjects
	linkObject  link.Link
}

func NewEventMonitor() *EventMonitor {
	return &EventMonitor{
		messageChan: make(chan bpf.Event, 100),
	}
}

func (m *EventMonitor) Load() error {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}
	linkObject, err := link.Tracepoint("syscalls", "sys_enter_chdir", objs.TraceEnterChdir, nil)
	if err != nil {
		return err
	}
	m.linkObject = linkObject
	m.objects = objs
	return nil
}

func (m *EventMonitor) Listen(ctx context.Context, messageChan chan<- bpf.Event) error {
	reader, err := ringbuf.NewReader(m.objects.Events)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				{
					data, err := reader.Read()
					if err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							return
						}
					}
					bpfEvent := (*bpfEvent)(unsafe.Pointer(&data.RawSample[0]))
					path := utils.ConvertCString(bpfEvent.Path[:])
					messageChan <- bpf.Event{
						EventType: bpf.Chdir,
						Pid:       int(bpfEvent.Pid),
						Path:      path,
					}
				}
			}
		}
	}()
	return nil
}

func (m *EventMonitor) Close() {
	m.linkObject.Close()
	m.objects.Close()
}
