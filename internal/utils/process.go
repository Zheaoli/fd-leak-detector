package utils

import (
	"os"
	"path/filepath"
	"strconv"
)

func IsSymlink(path string) bool {
	file, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return file.Mode()&os.ModeSymlink != 0
}

func GetProcessFsPath(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/root" + "/" + file
}

func GetProcessCmdline(pid int) string {
	cmdline := filepath.Join("/proc/", strconv.Itoa(pid), "cmdline")
	cmdlineBytes, err := os.ReadFile(cmdline)
	if err != nil {
		return ""
	}
	return string(cmdlineBytes)
}
