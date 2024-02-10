package chdir

import (
	"os"
	"regexp"

	"fd-leak-detector/internal/bpf"
	"fd-leak-detector/internal/utils"

	"github.com/sirupsen/logrus"
)

const targetDirectoryPattern = "/proc/self/fd/[0-9]+"

var (
	targetDirectoryRegex = regexp.MustCompile(targetDirectoryPattern)
)

func detectFdLeak(event bpf.Event, path string, recursionLevel uint8) {
	if recursionLevel >= 50 {
		return
	}
	if targetDirectoryRegex.MatchString(path) {
		logrus.Infof("Detected fd leak, pid: %d, path: %s", event.Pid, path)
		return
	}
	absolutPath := utils.GetProcessFsPath(event.Pid, path)
	if !utils.IsSymlink(absolutPath) {
		return
	}
	linkPath, err := os.Readlink(absolutPath)
	if err != nil {
		logrus.Warnf("Failed to read link: %s, error: %v", absolutPath, err)
		return
	}
	detectFdLeak(event, linkPath, recursionLevel+1)
}

func ProcessChdirEvent(event bpf.Event) {
	detectFdLeak(event, event.Path, 0)
}
