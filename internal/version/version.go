/*
Copyright The Athenz Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package version

import (
	"fmt"
	"os"
	"runtime"
)

func init() {
	if AppVersion == "" || GitCommit == "" {
		fmt.Fprintf(os.Stderr, "warning: AppVersion or GitCommit not set, this binary was built without -ldflags \"-X internal/version.AppVersion=... -X internal/version.GitCommit=...\"\n")
	}
}

type Version struct {
	AppVersion string `json:"appVersion"`
	GitCommit  string `json:"gitCommit"`
	GoVersion  string `json:"goVersion"`
	Compiler   string `json:"compiler"`
	Platform   string `json:"platform"`
}

// This variable block holds information used to build up the version string
var (
	AppVersion = ""
	GitCommit  = ""
)

func VersionInfo() Version {
	return Version{
		AppVersion: AppVersion,
		GitCommit:  GitCommit,
		GoVersion:  runtime.Version(),
		Compiler:   runtime.Compiler,
		Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
