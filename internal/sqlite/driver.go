package sqlite

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>

static int zp_bind_text(sqlite3_stmt *stmt, int idx, const char *v, int n) {
    return sqlite3_bind_text(stmt, idx, v, n, SQLITE_TRANSIENT);
}
static int zp_bind_blob(sqlite3_stmt *stmt, int idx, const void *v, int n) {
    return sqlite3_bind_blob(stmt, idx, v, n, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"unsafe"
)

func init() { sql.Register("zsqlite", &Driver{}) }

type Driver struct{}

type conn struct {
	mu sync.Mutex
	db *C.sqlite3
}

type stmt struct {
	c     *conn
	query string
}

type tx struct{ c *conn }

type result struct{ lastID, affected int64 }

type rows struct {
	c    *conn
	stmt *C.sqlite3_stmt
	cols []string
	done bool
}

func (d *Driver) Open(name string) (driver.Conn, error) {
	name = strings.TrimPrefix(name, "file:")
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var db *C.sqlite3
	rc := C.sqlite3_open_v2(cname, &db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil)
	if rc != C.SQLITE_OK {
		msg := "sqlite open failed"
		if db != nil {
			msg = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return nil, errors.New(msg)
	}
	C.sqlite3_busy_timeout(db, 5000)
	return &conn{db: db}, nil
}

func (c *conn) Prepare(query string) (driver.Stmt, error) { return &stmt{c: c, query: query}, nil }
func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db == nil {
		return nil
	}
	rc := C.sqlite3_close(c.db)
	if rc != C.SQLITE_OK {
		return c.err()
	}
	c.db = nil
	return nil
}
func (c *conn) Begin() (driver.Tx, error) {
	if _, err := c.exec(context.Background(), "BEGIN", nil); err != nil {
		return nil, err
	}
	return &tx{c: c}, nil
}
func (c *conn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if _, err := c.exec(ctx, "BEGIN", nil); err != nil {
		return nil, err
	}
	return &tx{c: c}, nil
}
func (c *conn) Ping(ctx context.Context) error {
	_, err := c.exec(ctx, "SELECT 1", nil)
	return err
}
func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.exec(ctx, query, args)
}
func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.query(ctx, query, args)
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }
func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	nv := make([]driver.NamedValue, len(args))
	for i, v := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return s.c.exec(context.Background(), s.query, nv)
}
func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	nv := make([]driver.NamedValue, len(args))
	for i, v := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return s.c.query(context.Background(), s.query, nv)
}
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.exec(ctx, s.query, args)
}
func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.query(ctx, s.query, args)
}

func (t *tx) Commit() error   { _, err := t.c.exec(context.Background(), "COMMIT", nil); return err }
func (t *tx) Rollback() error { _, err := t.c.exec(context.Background(), "ROLLBACK", nil); return err }

func (r result) LastInsertId() (int64, error) { return r.lastID, nil }
func (r result) RowsAffected() (int64, error) { return r.affected, nil }

func (c *conn) exec(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.prepareLocked(query)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(st)
	if err := c.bindLocked(st, args); err != nil {
		return nil, err
	}
	for {
		rc := C.sqlite3_step(st)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc == C.SQLITE_ROW {
			continue
		}
		return nil, c.err()
	}
	return result{lastID: int64(C.sqlite3_last_insert_rowid(c.db)), affected: int64(C.sqlite3_changes(c.db))}, nil
}

func (c *conn) query(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	st, err := c.prepareLocked(query)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err := c.bindLocked(st, args); err != nil {
		C.sqlite3_finalize(st)
		c.mu.Unlock()
		return nil, err
	}
	n := int(C.sqlite3_column_count(st))
	cols := make([]string, n)
	for i := 0; i < n; i++ {
		cols[i] = C.GoString(C.sqlite3_column_name(st, C.int(i)))
	}
	// rows owns the connection lock until Close/EOF to keep sqlite3_stmt access serialized.
	return &rows{c: c, stmt: st, cols: cols}, nil
}

func (c *conn) prepareLocked(query string) (*C.sqlite3_stmt, error) {
	cq := C.CString(query)
	defer C.free(unsafe.Pointer(cq))
	var st *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(c.db, cq, -1, &st, nil); rc != C.SQLITE_OK {
		return nil, c.err()
	}
	return st, nil
}

func (c *conn) bindLocked(st *C.sqlite3_stmt, args []driver.NamedValue) error {
	for i, a := range args {
		idx := C.int(i + 1)
		var rc C.int
		switch v := a.Value.(type) {
		case nil:
			rc = C.sqlite3_bind_null(st, idx)
		case int64:
			rc = C.sqlite3_bind_int64(st, idx, C.sqlite3_int64(v))
		case int:
			rc = C.sqlite3_bind_int64(st, idx, C.sqlite3_int64(v))
		case int32:
			rc = C.sqlite3_bind_int64(st, idx, C.sqlite3_int64(v))
		case bool:
			if v {
				rc = C.sqlite3_bind_int(st, idx, 1)
			} else {
				rc = C.sqlite3_bind_int(st, idx, 0)
			}
		case float64:
			rc = C.sqlite3_bind_double(st, idx, C.double(v))
		case float32:
			rc = C.sqlite3_bind_double(st, idx, C.double(v))
		case string:
			cs := C.CString(v)
			rc = C.zp_bind_text(st, idx, cs, C.int(len(v)))
			C.free(unsafe.Pointer(cs))
		case []byte:
			if len(v) == 0 {
				rc = C.zp_bind_blob(st, idx, nil, 0)
			} else {
				p := C.CBytes(v)
				rc = C.zp_bind_blob(st, idx, p, C.int(len(v)))
				C.free(p)
			}
		default:
			return fmt.Errorf("unsupported sqlite bind type %T", a.Value)
		}
		if rc != C.SQLITE_OK {
			return c.err()
		}
	}
	return nil
}

func (c *conn) err() error {
	if c.db == nil {
		return errors.New("sqlite connection closed")
	}
	return errors.New(C.GoString(C.sqlite3_errmsg(c.db)))
}

func (r *rows) Columns() []string { return r.cols }
func (r *rows) Close() error {
	if r.done {
		return nil
	}
	r.done = true
	if r.stmt != nil {
		C.sqlite3_finalize(r.stmt)
		r.stmt = nil
	}
	r.c.mu.Unlock()
	return nil
}
func (r *rows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	rc := C.sqlite3_step(r.stmt)
	if rc == C.SQLITE_DONE {
		_ = r.Close()
		return io.EOF
	}
	if rc != C.SQLITE_ROW {
		err := r.c.err()
		_ = r.Close()
		return err
	}
	for i := range dest {
		col := C.int(i)
		switch C.sqlite3_column_type(r.stmt, col) {
		case C.SQLITE_INTEGER:
			dest[i] = int64(C.sqlite3_column_int64(r.stmt, col))
		case C.SQLITE_FLOAT:
			v := float64(C.sqlite3_column_double(r.stmt, col))
			if math.IsNaN(v) || math.IsInf(v, 0) {
				dest[i] = nil
			} else {
				dest[i] = v
			}
		case C.SQLITE_TEXT:
			p := C.sqlite3_column_text(r.stmt, col)
			n := C.sqlite3_column_bytes(r.stmt, col)
			dest[i] = C.GoStringN((*C.char)(unsafe.Pointer(p)), n)
		case C.SQLITE_BLOB:
			p := C.sqlite3_column_blob(r.stmt, col)
			n := C.sqlite3_column_bytes(r.stmt, col)
			if n == 0 {
				dest[i] = []byte{}
			} else {
				dest[i] = C.GoBytes(p, n)
			}
		default:
			dest[i] = nil
		}
	}
	return nil
}

var _ driver.Driver = (*Driver)(nil)
var _ driver.Conn = (*conn)(nil)
var _ driver.ExecerContext = (*conn)(nil)
var _ driver.QueryerContext = (*conn)(nil)
var _ driver.ConnBeginTx = (*conn)(nil)
var _ driver.Pinger = (*conn)(nil)
var _ driver.StmtExecContext = (*stmt)(nil)
var _ driver.StmtQueryContext = (*stmt)(nil)
