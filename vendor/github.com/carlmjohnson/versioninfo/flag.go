package versioninfo

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

// AddFlag adds -v and -version flags to the FlagSet.
// If triggered, the flags print version information and call os.Exit(0).
// If FlagSet is nil, it adds the flags to flag.CommandLine.
func AddFlag(f *flag.FlagSet) {
	if f == nil {
		f = flag.CommandLine
	}
	f.Var(boolFunc(printVersion), "v", "short alias for -version")
	f.Var(boolFunc(printVersion), "version", "print version information and exit")
}

func printVersion(b bool) error {
	if !b {
		return nil
	}
	fmt.Println("Version:", Version)
	fmt.Println("Revision:", Revision)
	if Revision != "unknown" {
		fmt.Println("Committed:", LastCommit.Format(time.RFC1123))
		if DirtyBuild {
			fmt.Println("Dirty Build")
		}
	}
	os.Exit(0)
	panic("unreachable")
}

type boolFunc func(bool) error

func (f boolFunc) IsBoolFlag() bool {
	return true
}

func (f boolFunc) String() string {
	return ""
}

func (f boolFunc) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	return f(b)
}
