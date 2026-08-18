package analytics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ZentWorks/ZentProxy/internal/db"
	"github.com/ZentWorks/ZentProxy/internal/model"
)

const analyticsCheckpoint = "access-jsonl"

type Tailer struct {
	store         *db.Store
	path          string
	retentionDays int
	maxLogBytes   int64
	reopenLogs    func() error
}

func New(store *db.Store, dataDir string, retentionDays int, maxLogBytes int64, reopenLogs func() error) *Tailer {
	return &Tailer{store: store, path: filepath.Join(dataDir, "logs", "access.jsonl"), retentionDays: retentionDays, maxLogBytes: maxLogBytes, reopenLogs: reopenLogs}
}

func (t *Tailer) Start(ctx context.Context) {
	_ = t.store.CleanupRawRequests(t.retentionDays)
	go t.run(ctx)
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = t.store.CleanupRawRequests(t.retentionDays)
			}
		}
	}()
}

func (t *Tailer) run(ctx context.Context) {
	var f *os.File
	var reader *bufio.Reader
	var offset int64
	var activePath string
	var processing bool
	processingPath := t.path + ".processing"

	open := func() bool {
		activePath = t.path
		processing = false
		if _, err := os.Stat(processingPath); err == nil {
			activePath = processingPath
			processing = true
		}
		var err error
		f, err = os.Open(activePath)
		if err != nil {
			return false
		}
		offset, err = t.store.AnalyticsOffset(analyticsCheckpoint)
		if err != nil {
			_ = f.Close()
			f = nil
			return false
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			f = nil
			return false
		}
		if offset < 0 || offset > st.Size() {
			offset = 0
			_ = t.store.SetAnalyticsOffset(analyticsCheckpoint, 0)
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			f = nil
			return false
		}
		reader = bufio.NewReader(f)
		return true
	}

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				_ = f.Close()
			}
			return
		default:
		}

		if f == nil {
			if !open() {
				sleepContext(ctx, 300*time.Millisecond)
				continue
			}
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			nextOffset := offset + int64(len(line))
			if ingestErr := t.ingest(strings.TrimSpace(line), nextOffset); ingestErr != nil {
				_, _ = f.Seek(offset, io.SeekStart)
				reader = bufio.NewReader(f)
				sleepContext(ctx, 300*time.Millisecond)
				continue
			}
			offset = nextOffset
			continue
		}

		if !errors.Is(err, io.EOF) {
			_ = f.Close()
			f = nil
			sleepContext(ctx, 300*time.Millisecond)
			continue
		}

		// A final partial JSON line has been consumed by ReadString. Rewind it until
		// OpenResty appends the newline and the event is complete.
		if len(line) > 0 {
			_, _ = f.Seek(offset, io.SeekStart)
			reader = bufio.NewReader(f)
			sleepContext(ctx, 100*time.Millisecond)
			continue
		}

		st, statErr := os.Stat(activePath)
		if statErr != nil {
			_ = f.Close()
			f = nil
			sleepContext(ctx, 150*time.Millisecond)
			continue
		}

		if processing {
			// No writer owns the processing file after a successful reopen. Remove first;
			// if we crash before resetting the checkpoint, current-file size detection
			// safely resets it on the next start without duplicating the processed file.
			_ = f.Close()
			f = nil
			if err := os.Remove(processingPath); err == nil || os.IsNotExist(err) {
				_ = t.store.SetAnalyticsOffset(analyticsCheckpoint, 0)
			}
			continue
		}

		if st.Size() < offset {
			_ = f.Close()
			f = nil
			_ = t.store.SetAnalyticsOffset(analyticsCheckpoint, 0)
			continue
		}

		if t.maxLogBytes > 0 && st.Size() >= t.maxLogBytes && offset >= st.Size() {
			_ = f.Close()
			f = nil
			if err := os.Rename(t.path, processingPath); err == nil {
				if t.reopenLogs != nil {
					if err := t.reopenLogs(); err != nil {
						_ = os.Rename(processingPath, t.path)
						sleepContext(ctx, time.Second)
						continue
					}
				}
				// In a local/test run there may be no OpenResty process to recreate the path.
				if _, err := os.Stat(t.path); os.IsNotExist(err) {
					file, createErr := os.OpenFile(t.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
					if createErr == nil {
						_ = file.Close()
					}
				}
				continue
			}
		}

		sleepContext(ctx, 150*time.Millisecond)
	}
}

type logLine struct {
	TS           string `json:"ts"`
	Host         string `json:"host"`
	IP           string `json:"ip"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Query        string `json:"query"`
	Status       int    `json:"status"`
	Bytes        int64  `json:"bytes"`
	RequestTime  string `json:"request_time"`
	UpstreamTime string `json:"upstream_time"`
	UserAgent    string `json:"user_agent"`
	Referer      string `json:"referer"`
	HTTPVersion  string `json:"http_version"`
	TLSVersion   string `json:"tls_version"`
	UpstreamAddr string `json:"upstream_addr"`
}

func (t *Tailer) ingest(line string, nextOffset int64) error {
	if line == "" {
		return t.store.SetAnalyticsOffset(analyticsCheckpoint, nextOffset)
	}
	var l logLine
	if json.Unmarshal([]byte(line), &l) != nil {
		return t.store.SetAnalyticsOffset(analyticsCheckpoint, nextOffset)
	}
	at, err := time.Parse(time.RFC3339, l.TS)
	if err != nil {
		return t.store.SetAnalyticsOffset(analyticsCheckpoint, nextOffset)
	}
	rt, _ := strconv.ParseFloat(l.RequestTime, 64)
	rt *= 1000
	var up *float64
	if v := firstFloat(l.UpstreamTime); v >= 0 {
		ms := v * 1000
		up = &ms
	}
	r := model.RawRequest{At: at, Host: l.Host, IP: l.IP, Method: l.Method, Path: l.Path, Query: l.Query, Status: l.Status, Bytes: l.Bytes, RequestTimeMS: rt, UpstreamTimeMS: up, UserAgent: l.UserAgent, Referer: l.Referer, HTTPVersion: l.HTTPVersion, TLSVersion: l.TLSVersion, ZentLoop: usesZentLoop(l.UpstreamAddr)}
	return t.store.InsertRawRequestWithOffset(analyticsCheckpoint, nextOffset, r)
}

func usesZentLoop(v string) bool {
	for _, part := range strings.Split(v, ",") {
		if strings.TrimSpace(part) == "127.0.0.1:18081" {
			return true
		}
	}
	return false
}

func firstFloat(v string) float64 {
	v = strings.TrimSpace(strings.Split(v, ",")[0])
	if v == "" || v == "-" {
		return -1
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return -1
	}
	return n
}

func sleepContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
