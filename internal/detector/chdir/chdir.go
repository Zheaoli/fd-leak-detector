package chdir

import (
	"fd-leak-detector/internal/bpf"

	"github.com/sirupsen/logrus"
)

func ProcessChdirEvent(event bpf.Event) {
	logrus.Infof("chdir event: %v", event)
}
