// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Walker is a CLI tool to walk over a set of directories and process all discovered files.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/fswalker"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"

	fspb "github.com/google/fswalker/proto/fswalker"
)

var (
	policyFile    = flag.String("c", "", "required policy file to use")
	outputFilePfx = flag.String("o", "", "path prefix for the output file to write")
	verbose       = flag.Bool("v", false, "when set to true, prints all discovered files including a metadata summary")
)

func walkCallback(walk *fspb.Walk) error {
	outpath, err := outputPath(*outputFilePfx)
	if err != nil {
		return err
	}
	walkBytes, err := proto.Marshal(walk)
	if err != nil {
		return err
	}
	return os.WriteFile(outpath, walkBytes, 0444)
}

func outputPath(pfx string) (string, error) {
	hn, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("error getting hostname: %v", err)
	}
	if pfx == "" {
		pfx, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("error getting current directory: %v", err)
		}
	}
	return filepath.Join(pfx, fswalker.WalkFilename(hn, time.Now())), nil
}

func main() {
	flag.Parse()

	if *policyFile == "" {
		log.Fatal("-c needs to be specified")
	}

	w, err := fswalker.WalkerFromPolicyFile(*policyFile)
	if err != nil {
		log.Fatal(err)
	}
	w.Verbose = *verbose
	w.WalkCallback = walkCallback

	// Walk the file system and wait for completion of processing.
	ctx := context.Background()
	if err := w.Run(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Metrics:")
	metrics := w.Counter.Metrics()
	slices.Sort(metrics)
	for _, k := range metrics {
		v, _ := w.Counter.Get(k)
		fmt.Printf("[%-30s] = %6d\n", k, v)
	}
}
