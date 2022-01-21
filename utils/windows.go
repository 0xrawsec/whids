//go:build windows
// +build windows

package utils

import (
	"fmt"
	"regexp"
	"strings"
	"syscall"

	"github.com/0xrawsec/golang-win32/win32/advapi32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

var (
	cDriveDeviceRe *regexp.Regexp
)

// ArgvFromCommandLine returns an argv slice given a command line
// provided in argument
func ArgvFromCommandLine(cl string) (argv []string, err error) {
	argc := int32(0)
	utf16ClPtr, err := syscall.UTF16PtrFromString(cl)
	if err != nil {
		return
	}
	utf16Argv, err := syscall.CommandLineToArgv(utf16ClPtr, &argc)
	if err != nil {
		return
	}
	argv = make([]string, argc)
	for i, utf16Ptr := range utf16Argv[:argc] {
		argv[i] = syscall.UTF16ToString((*utf16Ptr)[:])
	}
	return
}

// HideFile hides a file in Windows explorer
// source: https://stackoverflow.com/questions/54139606/how-to-create-a-hidden-file-in-windows-mac-linux
func HideFile(filename string) error {
	filenameW, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}
	err = syscall.SetFileAttributes(filenameW, syscall.FILE_ATTRIBUTE_HIDDEN)
	if err != nil {
		return err
	}
	return nil
}

func ResolveCDrive(path string) string {
	var devs []string
	var err error

	if cDriveDeviceRe == nil {
		if devs, err = kernel32.QueryDosDevice("C:"); err != nil {
			return path
		}
		if len(devs) > 0 {
			if cDriveDeviceRe, err = regexp.Compile(regexp.QuoteMeta(devs[0])); err != nil {
				return path
			}
		}
	}

	if cDriveDeviceRe != nil {
		res := cDriveDeviceRe.ReplaceAllString(path, "C:")
		return res
	}

	return path
}

func RegValue(path string) (i interface{}, err error) {
	var data []byte
	var dtype uint32

	if data, dtype, err = advapi32.RegGetValueFromString(path); err != nil {
		return
	} else {
		if i, err = advapi32.ParseRegValue(data, dtype); err != nil {
			return
		} else {
			return
		}
	}
}

func RegJoin(s ...string) string {
	for i := range s {
		s[i] = strings.Trim(s[i], `\`)
	}
	return strings.Join(s, `\`)
}

func RegValueToString(elems ...string) string {
	if i, err := RegValue(RegJoin(elems...)); err == nil {
		return fmt.Sprintf("%v", i)
	}
	return ""
}
