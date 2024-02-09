package detector

import (
	"context"

	"fd-leak-detector/internal/bpf"
	"fd-leak-detector/internal/detector/chdir"
)

func Detector(ctx context.Context, eventChan <-chan bpf.Event) error {
	needBreak := false
	for event := range eventChan {
		select {
		case <-ctx.Done():
			needBreak = true
		default:
			if event.EventType == bpf.Chdir {
				chdir.ProcessChdirEvent(event)
			}
			if needBreak {
				break
			}
		}
	}
	return nil
}
