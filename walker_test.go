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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/fswalker/internal/metrics"
	fspb "github.com/google/fswalker/proto/fswalker"
)

type outpathWriter string

func (o outpathWriter) writeWalk(walk *fspb.Walk) error {
	walkBytes, err := proto.Marshal(walk)
	if err != nil {
		return err
	}
	return os.WriteFile(string(o), walkBytes, 0444)
}

// testFile implements the os.FileInfo interface.
// For more details, see: https://golang.org/src/os/types.go?s=479:840#L11
type testFile struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
	sys     *syscall.Stat_t
}

func (t *testFile) Name() string       { return t.name }
func (t *testFile) Size() int64        { return t.size }
func (t *testFile) Mode() os.FileMode  { return t.mode }
func (t *testFile) ModTime() time.Time { return t.modTime }
func (t *testFile) IsDir() bool        { return t.isDir }
func (t *testFile) Sys() interface{}   { return t.sys }

func TestWalkerFromPolicyFile(t *testing.T) {
	path := filepath.Join(testdataDir, "defaultClientPolicy.asciipb")
	wantPol := &fspb.Policy{
		Version:         1,
		MaxHashFileSize: 1048576,
		Include: []string{
			"/",
		},
		Exclude: []string{
			"/usr/src/linux-headers",
			"/usr/share/",
			"/proc/",
			"/sys/",
			"/tmp/",
			"/var/log/",
			"/var/tmp/",
		},
	}

	wlkr, err := WalkerFromPolicyFile(path)
	if err != nil {
		t.Errorf("WalkerFromPolicyFile() error: %v", err)
		return
	}
	diff := cmp.Diff(wlkr.pol, wantPol, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("WalkerFromPolicyFile() policy: diff (-want +got):\n%s", diff)
	}
}

func TestIsExcluded(t *testing.T) {
	testCases := []struct {
		desc     string
		path     string
		excludes []string
		wantExcl bool
	}{
		{
			desc:     "test exclusion with empty list",
			path:     "/foo",
			excludes: []string{},
			wantExcl: false,
		}, {
			desc: "test exclusion with entries but no match",
			path: "/foo",
			excludes: []string{
				"/tmp/",
				"/home/user2/",
				"/var/log/",
			},
			wantExcl: false,
		}, {
			desc: "test exclusion with dir match",
			path: "/tmp/foo",
			excludes: []string{
				"/tmp/",
			},
			wantExcl: true,
		}, {
			desc: "test exclusion with file match",
			path: "/tmp/some_file",
			excludes: []string{
				"/tmp/some_file",
			},
			wantExcl: true,
		}, {
			desc: "test exclusion with exact dir match",
			path: "/tmp/some_file/",
			excludes: []string{
				"/tmp/some_file/",
			},
			wantExcl: true,
		}, {
			desc: "test exclusion with different file/dir",
			path: "/tmp/some_file/",
			excludes: []string{
				"/tmp/some_file",
			},
			wantExcl: false,
		},
	}

	for _, tc := range testCases {
		gotExcl := isExcluded(tc.path, tc.excludes)
		if gotExcl != tc.wantExcl {
			t.Errorf("isExcluded() %q = %v; want %v", tc.desc, gotExcl, tc.wantExcl)
		}
	}
}

func TestConvert(t *testing.T) {
	wlkr := &Walker{
		pol: &fspb.Policy{
			ExcludeHashing: []string{
				testdataDir,
			},
			MaxHashFileSize: 1048576,
		},
	}
	path := filepath.Join(testdataDir, "hashSumTest")
	st := syscall.Stat_t{
		Dev:     1,
		Ino:     123456,
		Nlink:   2,
		Mode:    640,
		Uid:     123,
		Gid:     456,
		Rdev:    111,
		Size:    100,
		Blksize: 128,
		Blocks:  10,
	}
	atime := syscall.Timespec{Sec: time.Now().Unix(), Nsec: 100}
	mtime := syscall.Timespec{Sec: time.Now().Unix(), Nsec: 200}
	ctime := syscall.Timespec{Sec: time.Now().Unix(), Nsec: 300}
	st = setTimes(st, atime, mtime, ctime)
	h := sha256.New()

	info := &testFile{
		name:    "hashSumTest",
		size:    100,
		mode:    os.FileMode(0640),
		modTime: time.Now(),
		isDir:   false,
		sys:     &st,
	}

	mts := tspb.New(info.ModTime())
	wantFile := &fspb.File{
		Version: 1,
		Path:    path,
		Info: &fspb.FileInfo{
			Name:     "hashSumTest",
			Size:     100,
			Mode:     0640,
			Modified: mts,
			IsDir:    false,
		},
		Stat: &fspb.FileStat{
			Dev:     1,
			Inode:   123456,
			Nlink:   2,
			Mode:    640,
			Uid:     123,
			Gid:     456,
			Rdev:    111,
			Size:    100,
			Blksize: 128,
			Blocks:  10,
			Atime:   &tspb.Timestamp{Seconds: atime.Sec, Nanos: int32(atime.Nsec)},
			Mtime:   &tspb.Timestamp{Seconds: mtime.Sec, Nanos: int32(mtime.Nsec)},
			Ctime:   &tspb.Timestamp{Seconds: ctime.Sec, Nanos: int32(ctime.Nsec)},
		},
		Fingerprint: []*fspb.Fingerprint{
			{
				Method: fspb.Fingerprint_SHA256,
				Value:  "aeb02544df0ef515b21cab81ad5c0609b774f86879bf7e2e42c88efdaab2c75f",
			},
		},
	}

	gotFile := wlkr.convert(&fileInfo{path: path, info: nil}, h, nil) // ensuring there is no problems with nil file stats.
	if wantFile.Path != gotFile.Path {
		t.Errorf("convert() path = %q; want: %q", gotFile.Path, wantFile.Path)
	}

	gotFile = wlkr.convert(&fileInfo{path: path, info: info}, h, nil)
	diff := cmp.Diff(gotFile, wantFile, cmp.Comparer(proto.Equal))
	if diff != "" {
		t.Errorf("convert() File proto: diff (-want +got):\n%s", diff)
	}
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	tmpfile, err := os.CreateTemp("", "walk.pb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	writer := outpathWriter(tmpfile.Name())
	wlkr := &Walker{
		pol: &fspb.Policy{
			Include: []string{
				testdataDir,
			},
			ExcludeHashing: []string{
				testdataDir,
			},
			MaxHashFileSize: 1048576,
		},
		WalkCallback: writer.writeWalk,
		Counter:      &metrics.Counter{},
	}

	if err := wlkr.Run(ctx); err != nil {
		t.Errorf("Run() error: %v", err)
		return
	}

	wantMetrics := []string{
		"dir-count",
		"file-size-sum",
		"file-count",
		"file-hash-count",
	}
	sort.Strings(wantMetrics)
	m := wlkr.Counter.Metrics()
	sort.Strings(m)
	if !reflect.DeepEqual(wantMetrics, m) {
		t.Errorf("wlkr.Counter.Metrics() = %q; want %q", m, wantMetrics)
	}
	for _, k := range m {
		if _, ok := wlkr.Counter.Get(k); !ok {
			t.Errorf("wlkr.Counter.Get(%q): not ok", k)
		}
	}

	b, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Errorf("unable to read file %q: %v", tmpfile.Name(), err)
	}
	walk := &fspb.Walk{}
	if err := proto.Unmarshal(b, walk); err != nil {
		t.Errorf("unabled to decode proto file %q: %v", tmpfile.Name(), err)
	}
	st := walk.StartWalk.AsTime()
	et := walk.StopWalk.AsTime()
	if st.Before(time.Now().Add(-time.Hour)) || st.After(et) {
		t.Errorf("start time is not within bounds: %s < %s < %s", time.Now().Add(-time.Hour), st, et)
	}
	if et.Before(st) || et.After(time.Now()) {
		t.Errorf("stop time is not within bounds: %s < %s < %s", st, et, time.Now())
	}
	if walk.Hostname == "" {
		t.Error("walk.Hostname is empty")
	}
	if walk.Id == "" {
		t.Error("walk.Id is empty")
	}
}
