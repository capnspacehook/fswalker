package fsstat

import (
	"fmt"
	"os"
	"syscall"

	fspb "github.com/google/fswalker/proto/fswalker"
)

// ToStat returns a fspb.ToStat with the file info from the given file
func ToStat(info os.FileInfo) (*fspb.FileStat, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return &fspb.FileStat{
			Dev:     stat.Dev,
			Inode:   stat.Ino,
			Nlink:   stat.Nlink,
			Mode:    stat.Mode,
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    stat.Rdev,
			Size:    stat.Size,
			Blksize: stat.Blksize,
			Blocks:  stat.Blocks,
			Atime:   timespec2Timestamp(stat.Atim),
			Mtime:   timespec2Timestamp(stat.Mtim),
			Ctime:   timespec2Timestamp(stat.Ctim),
		}, nil
	}

	return nil, fmt.Errorf("unable to get file stat for %#v", info)
}

func Dev(info os.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Dev, true
	}
	return 0, false
}
