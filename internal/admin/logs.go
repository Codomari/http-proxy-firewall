package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

const maxLogRead = 1 << 20

type logTail struct {
	mu         sync.Mutex
	path       string
	info       os.FileInfo
	generation uint64
	maxLine    int // Zero retains the service viewer's 4 KiB display limit.
}

type logCursor struct {
	Generation uint64 `json:"g"`
	Offset     int64  `json:"o"`
	Anchor     string `json:"a"`
}

type logBatch struct {
	Lines   []string `json:"lines"`
	Cursor  string   `json:"cursor"`
	Reset   bool     `json:"reset"`
	More    bool     `json:"more"`
	Limited bool     `json:"limited"`
}

// Each request reopens the fixed service log so rename-based rotation works.
// A cursor anchor also detects copytruncate followed by rapid regrowth.
func (l *logTail) read(raw string) (logBatch, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := logBatch{Lines: []string{}}
	file, err := os.Open(l.path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("log is not a regular file")
	}
	if l.info == nil || !os.SameFile(l.info, info) {
		l.generation++
	}
	l.info = info
	var cursor logCursor
	if len(raw) <= 512 {
		if data, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
			_ = json.Unmarshal(data, &cursor)
		}
	}
	valid := raw != "" && cursor.Generation == l.generation && cursor.Offset >= 0 && cursor.Offset <= info.Size() && cursor.Anchor == logAnchor(file, cursor.Offset)
	result.Reset = !valid
	start := cursor.Offset
	if !valid {
		start = max(int64(0), info.Size()-maxLogRead)
	}
	count := min(int64(maxLogRead), info.Size()-start)
	data := make([]byte, int(count))
	n, err := file.ReadAt(data, start)
	if err != nil && err != io.EOF {
		return result, err
	}
	data = data[:n]
	end := start + int64(n)
	// Do not publish an unfinished final line until its newline arrives.
	if last := bytes.LastIndexByte(data, '\n'); last >= 0 {
		data = data[:last+1]
		end = start + int64(last+1)
	} else if len(data) < maxLogRead {
		data = nil
		end = start
	} else {
		// An oversized line must not pin the cursor indefinitely.
		result.Limited = true
	}
	if !valid && start > 0 {
		result.Limited = true
		if first := bytes.IndexByte(data, '\n'); first >= 0 {
			data = data[first+1:]
		} else {
			data = nil
		}
	}
	if len(data) > 0 {
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		if !valid && len(lines) > 100 {
			lines = lines[len(lines)-100:]
		}
		limit := l.maxLine
		if limit == 0 {
			limit = 4096
		}
		for _, line := range lines {
			line = strings.TrimSuffix(line, "\r")
			if len(line) > limit {
				line = line[:limit] + " … [line truncated]"
				result.Limited = true
			}
			result.Lines = append(result.Lines, line)
		}
	}
	result.More = end < info.Size() && int64(n) == maxLogRead
	cursor = logCursor{Generation: l.generation, Offset: end, Anchor: logAnchor(file, end)}
	encoded, _ := json.Marshal(cursor)
	result.Cursor = base64.RawURLEncoding.EncodeToString(encoded)
	return result, nil
}

func logAnchor(file *os.File, offset int64) string {
	data := make([]byte, int(min(offset, int64(64))))
	n, _ := file.ReadAt(data, offset-int64(len(data)))
	sum := sha256.Sum256(data[:n])
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
