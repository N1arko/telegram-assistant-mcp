// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxMedia = 5 * 1024 * 1024

type Request struct {
	Op           string   `json:"op"`
	ChatID       string   `json:"chat_id"`
	MessageID    string   `json:"message_id"`
	Cursor       string   `json:"cursor"`
	Query        string   `json:"query"`
	Limit        int      `json:"limit"`
	RequestID    string   `json:"request_id"`
	Text         string   `json:"text"`
	ReplyTo      string   `json:"reply_to"`
	Data         string   `json:"data_base64"`
	Kind         string   `json:"media_kind"`
	MIME         string   `json:"mime_type"`
	Filename     string   `json:"filename"`
	PhoneNumbers []string `json:"phone_numbers,omitempty"`
}
type Transport interface {
	Connected() bool
	Send(context.Context, Request, string) (Record, error)
	Download(context.Context, Record) ([]byte, error)
}
type Bridge struct {
	cfg   Config
	store *Store
	wa    Transport
	token string
	mu    sync.Mutex
	calls []time.Time
	clock func() time.Time
}

func fail(code string) map[string]any { return map[string]any{"error": code} }
func (b *Bridge) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-WhatsApp-Account", b.cfg.account())
	if r.Host != b.cfg.address() || len(r.Header.Values("Origin")) != 0 {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(fail("bridge_forbidden"))
		return
	}
	if len(r.Header.Values("X-WhatsApp-Account")) != 1 || r.Header.Get("X-WhatsApp-Account") != b.cfg.account() {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(fail("account_mismatch"))
		return
	}
	if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+b.token)) != 1 {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(fail("unauthorized"))
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/call" || r.URL.RawQuery != "" {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(fail("not_found"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024*1024)
	var q Request
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(fail("invalid_request"))
		return
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(fail("invalid_request"))
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	valid := b.calls[:0]
	for _, t := range b.calls {
		if now.Sub(t) < time.Minute {
			valid = append(valid, t)
		}
	}
	b.calls = valid
	if len(b.calls) >= 120 {
		json.NewEncoder(w).Encode(fail("rate_limited"))
		return
	}
	b.calls = append(b.calls, now)
	result := b.call(r.Context(), q)
	json.NewEncoder(w).Encode(result)
}
func (b *Bridge) call(ctx context.Context, q Request) map[string]any {
	if q.Op == "status" {
		state := "disconnected"
		if b.wa.Connected() {
			state = "connected"
		}
		if s, ok := b.wa.(interface{ State() string }); ok {
			state = s.State()
		}
		var chunks int
		var progress sql.NullInt64
		_ = b.store.db.QueryRow("SELECT COUNT(*),MAX(progress) FROM sync_chunks").Scan(&chunks, &progress)
		return map[string]any{"account_id": b.cfg.account(), "connected": b.wa.Connected(), "session_state": state, "write_enabled": b.cfg.WriteEnabled, "read_access": b.cfg.readMode(), "write_access": b.cfg.writeMode(), "history_complete": false, "coverage": "locally_cached_partial", "cached_sync_chunks": chunks, "reported_sync_progress": progress.Int64}
	}
	if q.Op == "resolve_recipients" {
		return b.resolve(ctx, q.PhoneNumbers)
	}
	if q.Op == "list_chats" {
		if q.Limit < 1 || q.Limit > 20 {
			return fail("invalid_limit")
		}
		v, e := b.store.chats(q, b.cfg.canRead)
		if e != nil {
			return fail("invalid_cursor_or_storage")
		}
		return v
	}
	if !b.cfg.canRead(q.ChatID) {
		return fail("chat_not_allowed")
	}
	switch q.Op {
	case "history", "search":
		if q.Limit < 1 || q.Limit > 20 || len(q.Query) > 256 || (q.Op == "search" && strings.TrimSpace(q.Query) == "") {
			return fail("invalid_argument")
		}
		v, e := b.store.history(q)
		if e != nil {
			return fail("invalid_cursor_or_storage")
		}
		return v
	case "get_media":
		if !idPattern.MatchString(q.MessageID) {
			return fail("invalid_message")
		}
		r, e := b.store.record(q.ChatID, q.MessageID)
		if e != nil {
			return fail("message_not_cached")
		}
		if r.Kind == "" {
			return fail("no_media")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		data, e := b.wa.Download(ctx, r)
		if e != nil {
			return fail("media_unavailable")
		}
		if len(data) > maxMedia {
			return fail("media_too_large")
		}
		return map[string]any{"data_base64": base64.StdEncoding.EncodeToString(data), "media_kind": r.Kind, "mime_type": r.MIME, "filename": r.Filename}
	case "send_text", "send_media":
		return b.send(ctx, q)
	case "send_status":
		if !requestPattern.MatchString(q.RequestID) {
			return fail("invalid_request_id")
		}
		var id, status string
		e := b.store.db.QueryRow("SELECT message_id,status FROM sends WHERE request_id=? AND chat=?", q.RequestID, q.ChatID).Scan(&id, &status)
		if e != nil {
			return fail("request_not_found")
		}
		_, e = b.store.record(q.ChatID, id)
		return map[string]any{"status": status, "message_id": id, "observed_in_local_history": e == nil, "delivery_receipt": false, "read_receipt": false}
	}
	return fail("unknown_operation")
}
func (b *Bridge) send(ctx context.Context, q Request) map[string]any {
	if !b.cfg.canWrite(q.ChatID) {
		return fail("write_disabled")
	}
	if !requestPattern.MatchString(q.RequestID) || len([]rune(q.Text)) > 2000 || (q.ReplyTo != "" && !idPattern.MatchString(q.ReplyTo)) {
		return fail("invalid_argument")
	}
	if q.Op == "send_text" && (strings.TrimSpace(q.Text) == "" || q.Data != "") {
		return fail("invalid_argument")
	}
	if q.Op == "send_media" {
		data, e := base64.StdEncoding.Strict().DecodeString(q.Data)
		if e != nil || len(data) == 0 || len(data) > maxMedia || !validMedia(q.Kind, q.MIME, data) || !safeFilename(q.Filename) {
			return fail("invalid_media")
		}
	}
	if q.Kind == "audio" && q.Text != "" {
		return fail("audio_caption_unsupported")
	}
	if q.ReplyTo != "" {
		if _, e := b.store.record(q.ChatID, q.ReplyTo); e != nil {
			return fail("reply_not_cached")
		}
	}
	// Hash the complete payload. Reusing a key for different content is an error.
	canonical, _ := json.Marshal(q)
	sum := sha256.Sum256(canonical)
	fingerprint := hex.EncodeToString(sum[:])
	tx, e := b.store.db.Begin()
	if e != nil {
		return fail("storage_unavailable")
	}
	defer tx.Rollback()
	var prior, id, status string
	e = tx.QueryRow("SELECT fingerprint,message_id,status FROM sends WHERE request_id=?", q.RequestID).Scan(&prior, &id, &status)
	if e == nil {
		if prior != fingerprint {
			return fail("request_id_conflict")
		}
		return map[string]any{"status": status, "message_id": id, "duplicate_request": true, "delivery_receipt": false}
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return fail("storage_unavailable")
	}
	if !b.wa.Connected() {
		return fail("session_unavailable")
	}
	now := b.clock().Unix()
	var minute, day int
	// Global quotas also bound each chat; failures and unknown results consume quota.
	if e = tx.QueryRow("SELECT COALESCE(SUM(created>?),0),COUNT(*) FROM sends WHERE created>?", now-60, now-86400).Scan(&minute, &day); e != nil {
		return fail("storage_unavailable")
	}
	if minute >= b.cfg.PerMinute || day >= b.cfg.PerDay {
		return fail("send_quota_exceeded")
	}
	id = "3EB0" + strings.ToUpper(fingerprint[:32])
	// Commit unknown BEFORE any upload/send. A crash at every subsequent point is terminal.
	if _, e = tx.Exec("INSERT INTO sends VALUES(?,?,?,?,?,?)", q.RequestID, fingerprint, q.ChatID, id, "unknown", now); e != nil {
		return fail("storage_unavailable")
	}
	if e = tx.Commit(); e != nil {
		return fail("storage_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	record, e := b.wa.Send(ctx, q, id)
	if e == nil {
		// Persisting the ack is required before reporting server_accepted.
		if _, e = b.store.db.Exec("UPDATE sends SET status='server_accepted' WHERE request_id=?", q.RequestID); e == nil {
			status = "server_accepted"
			_ = b.store.put(q.ChatID, id, now, record)
		} else {
			status = "unknown"
		}
	} else {
		status = "unknown"
	}
	return map[string]any{"status": status, "message_id": id, "delivery_receipt": false, "read_receipt": false}
}

func safeFilename(s string) bool {
	return len(s) > 0 && len(s) <= 128 && !strings.ContainsAny(s, "/\\\x00\r\n") && s != "." && s != ".."
}
func validMedia(kind, mime string, b []byte) bool {
	switch kind {
	case "photo":
		return (mime == "image/jpeg" || mime == "image/png") && http.DetectContentType(b) == mime
	case "document":
		return mime == "application/pdf" && strings.HasPrefix(string(b), "%PDF-") || mime == "application/octet-stream"
	case "audio":
		return mime == "audio/ogg" && strings.HasPrefix(string(b), "OggS") || mime == "audio/mpeg" && (strings.HasPrefix(string(b), "ID3") || (len(b) > 1 && b[0] == 255 && b[1]&224 == 224)) || mime == "audio/wav" && http.DetectContentType(b) == "audio/wave" || mime == "audio/mp4" && len(b) > 12 && string(b[4:8]) == "ftyp"
	}
	return false
}
