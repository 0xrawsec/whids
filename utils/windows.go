// +build windows

package utils

import "syscall"

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
