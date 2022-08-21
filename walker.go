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

package fswalker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/uuid"
	tspb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/fswalker/internal/fsstat"
	"github.com/google/fswalker/internal/metrics"
	fspb "github.com/google/fswalker/proto/fswalker"
)

const (
	// Versions for compatibility comparison.
	fileVersion = 1
	walkVersion = 1

	// Unique names for each counter - used by the counter output processor.
	countFiles       = "file-count"
	countDirectories = "dir-count"
	countFileSizeSum = "file-size-sum"
	countStatErr     = "file-stat-errors"
	countHashes      = "file-hash-count"
)

var (
	// Number of workers
	parallelism = runtime.NumCPU()
)

// Walker is able to walk a file structure starting with a list of given includes
// as roots. All paths starting with any prefix specified in the excludes are
// ignored. The list of specific files in the hash list are read and a hash sum
// built for each. Note that this is expensive and should not be done for large
// files or a large number of files.
type Walker struct {
	// pol is the configuration defining which paths to include and exclude from the walk.
	pol *fspb.Policy

	// walk collects all processed files during a run.
	walk   *fspb.Walk
	walkMu sync.Mutex

	// Function to call once the Walk is complete i.e. to inspect or write the Walk.
	WalkCallback WalkCallback

	// Verbose, when true, makes Walker print file metadata to stdout.
	Verbose bool

	// Counter records stats over all processed files, if non-nil.
	Counter *metrics.Counter
}

// WalkCallback is called by Walker at the end of the Run.
// The callback is typically used to dump the walk to disk and/or perform any other checks.
// The error return value is propagated back to the Run callers.
type WalkCallback func(*fspb.Walk) error

type fileInfo struct {
	path string
	info fs.FileInfo
}

type workerErr struct {
	path string
	err  string
}

// WalkerFromPolicyFile creates a new Walker based on a policy path.
func WalkerFromPolicyFile(path string) (*Walker, error) {
	pol := &fspb.Policy{}
	if err := readTextProto(path, pol); err != nil {
		return nil, err
	}
	return &Walker{
		pol:     pol,
		Counter: &metrics.Counter{},
	}, nil
}

// Run is the main function of Walker. It discovers all files under included paths
// (minus excluded ones) and processes them.
// This does NOT follow symlinks - fortunately we don't need it either.
func (w *Walker) Run(ctx context.Context) error {
	walkID := uuid.New().String()
	hn, err := os.Hostname()
	if err != nil {
		return err
	}
	w.walk = &fspb.Walk{
		Version:   walkVersion,
		Id:        walkID,
		Policy:    w.pol,
		Hostname:  hn,
		StartWalk: tspb.Now(),
	}

	fileCh := make(chan *fileInfo, 64)
	errCh := make(chan *workerErr)
	done := make(chan struct{})
	var workerErrs []*workerErr

	var wg sync.WaitGroup
	wg.Add(parallelism)

	// start workers to hash and build file info concurrently
	for i := 0; i < parallelism; i++ {
		go func() {
			defer wg.Done()
			w.worker(fileCh, errCh)
		}()
	}

	// start goroutine to store worker errors
	go func() {
		for {
			for werr := range errCh {
				workerErrs = append(workerErrs, werr)
				log.Printf("ERROR: %s: %s", werr.path, werr.err)
			}
			done <- struct{}{}
		}
	}()

	w.preformWalk(fileCh)

	close(fileCh)
	wg.Wait()

	close(errCh)
	<-done

	for _, werr := range workerErrs {
		w.addNotificationToWalk(fspb.Notification_ERROR, werr.path, werr.err)
	}

	// Finishing work by writing out the report.
	w.walk.StopWalk = tspb.Now()
	if w.WalkCallback == nil {
		return nil
	}
	return w.WalkCallback(w.walk)
}

// worker is a worker routine that reads paths from chPaths and walks all the files and
// subdirectories until the channel is exhausted. All discovered files are converted to
// File and processed with w.process().
func (w *Walker) preformWalk(fileCh chan<- *fileInfo) error {
	for _, path := range w.pol.Include {
		path = filepath.Clean(path)
		baseInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to get file info for base path %q: %v", path, err)
		}
		baseDev, err := fsstat.DevNumber(baseInfo)
		if err != nil {
			return fmt.Errorf("unable to get file stat on base path %q: %v", path, err)
		}

		if err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			p = NormalizePath(p, d.IsDir())
			if err != nil {
				msg := fmt.Sprintf("failed to walk %q: %s", p, err)
				log.Print(msg)
				w.addNotificationToWalk(fspb.Notification_WARNING, p, msg)
				return nil
			}

			// Checking various exclusions based on flags in the walker policy.
			if isExcluded(p, w.pol.Exclude) {
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, fmt.Sprintf("skipping %q: excluded", p))
				}
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if w.pol.MaxDirectoryDepth > 0 && d.IsDir() && w.relDirDepth(path, p) > w.pol.MaxDirectoryDepth {
				w.addNotificationToWalk(fspb.Notification_WARNING, p, fmt.Sprintf("skipping %q: more than %d into base path %q", p, w.pol.MaxDirectoryDepth, path))
				return filepath.SkipDir
			}

			info, err := d.Info()
			if err != nil {
				msg := fmt.Sprintf("failed to stat %q: %s", p, err)
				log.Print(msg)
				w.addNotificationToWalk(fspb.Notification_WARNING, p, msg)
				return nil
			}

			if w.pol.IgnoreIrregularFiles && !info.Mode().IsRegular() && !d.IsDir() {
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, fmt.Sprintf("skipping %q: irregular file (mode: %s)", p, info.Mode()))
				}
				return nil
			}
			dev, ok := fsstat.Dev(info)
			if !w.pol.WalkCrossDevice && ok && baseDev != dev {
				msg := fmt.Sprintf("skipping %q: file is on different device", p)
				log.Print(msg)
				if w.Verbose {
					w.addNotificationToWalk(fspb.Notification_INFO, p, msg)
				}
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			fileCh <- &fileInfo{
				path: p,
				info: info,
			}

			return nil
		}); err != nil {
			return fmt.Errorf("error walking root include path %q: %v", path, err)
		}
	}
	return nil
}

// isExcluded determines whether a given path was asked to be excluded from scanning.
func isExcluded(path string, excluded []string) bool {
	for _, e := range excluded {
		if path == e {
			return true
		}
		// if e ends in a slash, treat it like a directory and match if e is the
		// dir of path
		if e[len(e)-1] == filepath.Separator && strings.HasPrefix(filepath.Dir(path)+string(filepath.Separator), e) {
			return true
		}
	}
	return false
}

func (w *Walker) addNotificationToWalk(s fspb.Notification_Severity, path, msg string) {
	w.walk.Notification = append(w.walk.Notification, &fspb.Notification{
		Severity: s,
		Path:     path,
		Message:  msg,
	})
	log.Printf("%s: %s: %s", s, path, msg)
}

// relDirDepth calculates the path depth relative to the origin.
func (w *Walker) relDirDepth(origin, path string) uint32 {
	return uint32(len(strings.Split(path, string(filepath.Separator))) - len(strings.Split(origin, string(filepath.Separator))))
}

func (w *Walker) worker(fileCh <-chan *fileInfo, errCh chan<- *workerErr) {
	hasher := sha256.New()
	for file := range fileCh {
		w.process(file, hasher, errCh)
	}
}

// process runs output functions for the given input File.
func (w *Walker) process(fi *fileInfo, h hash.Hash, errCh chan<- *workerErr) {
	f := w.convert(fi, h, errCh)

	// Print a short overview if we're running in verbose mode.
	if w.Verbose {
		fmt.Println(NormalizePath(f.Path, f.Info.IsDir))
		ts := f.Info.Modified.AsTime() // ignoring error in ts conversion
		info := []string{
			fmt.Sprintf("size(%d)", f.Info.Size),
			fmt.Sprintf("mode(%v)", os.FileMode(f.Info.Mode)),
			fmt.Sprintf("mTime(%v)", ts),
			fmt.Sprintf("uid(%d)", f.Stat.Uid),
			fmt.Sprintf("gid(%d)", f.Stat.Gid),
			fmt.Sprintf("inode(%d)", f.Stat.Inode),
		}
		for _, fp := range f.Fingerprint {
			info = append(info, fmt.Sprintf("%s(%s)", fspb.Fingerprint_Method_name[int32(fp.Method)], fp.Value))
		}
		fmt.Println(strings.Join(info, ", "))
	}

	// Add file to the walk which will later be written out to disk.
	w.walkMu.Lock()
	defer w.walkMu.Unlock()
	w.walk.File = append(w.walk.File, f)

	// Collect some metrics.
	if w.Counter != nil {
		if f.Info.IsDir {
			w.Counter.Add(1, countDirectories)
		} else {
			w.Counter.Add(1, countFiles)
		}
		w.Counter.Add(f.Info.Size, countFileSizeSum)
		if f.Stat == nil {
			w.Counter.Add(1, countStatErr)
		}
		if len(f.Fingerprint) > 0 {
			w.Counter.Add(1, countHashes)
		}
	}
}

// convert creates a File from the given information and if requested embeds the hash sum too.
func (w *Walker) convert(fi *fileInfo, h hash.Hash, errCh chan<- *workerErr) *fspb.File {
	path := filepath.Clean(fi.path)

	f := &fspb.File{
		Version: fileVersion,
		Path:    path,
	}

	if fi.info == nil {
		return f
	}

	var shaSum string
	// Only build the hash sum if requested and if it is not a directory.
	if !isExcluded(fi.path, w.pol.ExcludeHashing) && fi.info.Mode().IsRegular() && uint64(fi.info.Size()) <= w.pol.MaxHashFileSize {
		var err error
		shaSum, err = sha256sum(path, h)
		if err != nil {
			errCh <- &workerErr{
				path: f.Path,
				err:  fmt.Sprintf("unable to build hash: %v", err),
			}
		} else {
			f.Fingerprint = []*fspb.Fingerprint{
				{
					Method: fspb.Fingerprint_SHA256,
					Value:  shaSum,
				},
			}
		}
	}

	mts := tspb.New(fi.info.ModTime()) // ignoring the error and using default
	f.Info = &fspb.FileInfo{
		Name:     fi.info.Name(),
		Size:     fi.info.Size(),
		Mode:     uint32(fi.info.Mode()),
		Modified: mts,
		IsDir:    fi.info.IsDir(),
	}

	var err error
	if f.Stat, err = fsstat.ToStat(fi.info); err != nil {
		errCh <- &workerErr{
			path: f.Path,
			err:  err.Error(),
		}
	}

	return f
}
