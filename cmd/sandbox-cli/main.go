package main

import "github.com/rhpds/sandbox/internal/cli"

// Build info, injected via ldflags
var version = "development"
var buildCommit = "HEAD"
var buildTime = "undefined"

func main() {
	cli.SetBuildInfo(version, buildCommit, buildTime)
	cli.Execute()
}
