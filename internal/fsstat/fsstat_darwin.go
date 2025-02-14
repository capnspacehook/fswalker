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
			Dev:     uint64(stat.Dev),
			Inode:   stat.Ino,
			Nlink:   uint64(stat.Nlink),
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    stat.Size,
			Blksize: int64(stat.Blksize),
			Blocks:  stat.Blocks,
			Atime:   timespec2Timestamp(stat.Atimespec),
			Mtime:   timespec2Timestamp(stat.Mtimespec),
			Ctime:   timespec2Timestamp(stat.Ctimespec),
		}, nil
	}

	return nil, fmt.Errorf("unable to get file stat for %#v", info)
}

func Dev(info os.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), true
	}
	return 0, false
}
