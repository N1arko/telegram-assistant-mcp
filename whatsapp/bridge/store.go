// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	key  []byte
}
type Record struct {
	Sender   string `json:"sender"`
	Text     string `json:"text"`
	Kind     string `json:"kind"`
	MIME     string `json:"mime"`
	Filename string `json:"filename"`
	FromMe   bool   `json:"from_me"`
	Raw      []byte `json:"raw"`
}
type Cursor struct {
	Op    string `json:"op"`
	Chat  string `json:"chat"`
	Query string `json:"query"`
	Upper int64  `json:"upper"`
	TS    int64  `json:"ts"`
	ID    string `json:"id"`
}

func openStore(path string, key []byte) (*Store, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,chat TEXT NOT NULL,id TEXT NOT NULL,ts INTEGER NOT NULL,payload BLOB NOT NULL,UNIQUE(chat,id));
 CREATE INDEX IF NOT EXISTS history_order ON messages(chat,ts DESC,id DESC);
 CREATE TABLE IF NOT EXISTS sends(request_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,chat TEXT NOT NULL,message_id TEXT NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS sync_chunks(kind TEXT NOT NULL,chunk INTEGER NOT NULL,progress INTEGER NOT NULL,PRIMARY KEY(kind,chunk));`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db, aead, key}, nil
}
func (s *Store) seal(value []byte, aad string) ([]byte, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return s.aead.Seal(n, n, value, []byte(aad)), nil
}
func (s *Store) unseal(b []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(b) < n {
		return nil, errors.New("invalid_ciphertext")
	}
	return s.aead.Open(nil, b[:n], b[n:], []byte(aad))
}
func (s *Store) put(chat, id string, ts int64, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b, err = s.seal(b, chat+"\x00"+id)
	if err != nil {
		return err
	}
	// Sync replay never changes row sequence; a snapshot remains stable under backfill.
	_, err = s.db.Exec("INSERT OR IGNORE INTO messages(chat,id,ts,payload) VALUES(?,?,?,?)", chat, id, ts, b)
	return err
}
func (s *Store) record(chat, id string) (Record, error) {
	var b []byte
	var r Record
	err := s.db.QueryRow("SELECT payload FROM messages WHERE chat=? AND id=?", chat, id).Scan(&b)
	if err != nil {
		return r, err
	}
	b, err = s.unseal(b, chat+"\x00"+id)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	return r, err
}
func (s *Store) encode(c Cursor) string {
	b, _ := json.Marshal(c)
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(append(b, m.Sum(nil)...))
}
func (s *Store) cursor(token, op, chat, query string) (Cursor, error) {
	c := Cursor{Op: op, Chat: chat, Query: query, TS: 1 << 62, ID: "~"}
	if token == "" {
		err := s.db.QueryRow("SELECT COALESCE(MAX(seq),0) FROM messages").Scan(&c.Upper)
		return c, err
	}
	if len(token) > 4096 {
		return c, errors.New("invalid_cursor")
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) < 32 {
		return c, errors.New("invalid_cursor")
	}
	p := b[:len(b)-32]
	m := hmac.New(sha256.New, s.key)
	m.Write(p)
	if !hmac.Equal(m.Sum(nil), b[len(b)-32:]) || json.Unmarshal(p, &c) != nil || c.Op != op || c.Chat != chat || c.Query != query {
		return c, errors.New("invalid_cursor")
	}
	return c, nil
}
func publicRecord(chat, id string, ts int64, r Record) map[string]any {
	text := []rune(r.Text)
	truncated := len(text) > 2000
	if truncated {
		text = text[:2000]
	}
	return map[string]any{"chat_id": chat, "message_id": id, "timestamp": ts, "sender": r.Sender, "text": string(text), "truncated": truncated, "from_me": r.FromMe, "media_kind": r.Kind, "mime_type": r.MIME, "filename": r.Filename}
}
func (s *Store) history(q Request) (map[string]any, error) {
	sum := sha256.Sum256([]byte(q.Query))
	query := fmt.Sprintf("%x", sum)
	c, err := s.cursor(q.Cursor, q.Op, q.ChatID, query)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT id,ts,payload FROM messages WHERE chat=? AND seq<=? AND (ts<? OR (ts=? AND id<?)) ORDER BY ts DESC,id DESC LIMIT 1001", q.ChatID, c.Upper, c.TS, c.TS, c.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []any{}
	scanned := 0
	more := false
	for rows.Next() {
		if scanned == 1000 || len(out) == q.Limit {
			more = true
			break
		}
		var id string
		var ts int64
		var b []byte
		if err = rows.Scan(&id, &ts, &b); err != nil {
			return nil, err
		}
		plain, e := s.unseal(b, q.ChatID+"\x00"+id)
		if e != nil {
			return nil, e
		}
		var r Record
		if e = json.Unmarshal(plain, &r); e != nil {
			return nil, e
		}
		c.TS, c.ID = ts, id
		scanned++
		if q.Op == "history" || strings.Contains(strings.ToLower(r.Text), strings.ToLower(q.Query)) {
			out = append(out, publicRecord(q.ChatID, id, ts, r))
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	next := ""
	if more {
		next = s.encode(c)
	}
	return map[string]any{"messages": out, "next_cursor": next, "scanned": scanned, "history_complete": false, "coverage": "locally_cached_partial", "snapshot_sequence": c.Upper}, nil
}
func (s *Store) chats(q Request, allowed func(string) bool) (map[string]any, error) {
	c, err := s.cursor(q.Cursor, "list_chats", "", "")
	if err != nil {
		return nil, err
	}
	if q.Cursor == "" {
		c.ID = ""
	}
	rows, err := s.db.Query("SELECT chat,MIN(ts),MAX(ts),COUNT(*) FROM messages WHERE seq<=? AND chat>? GROUP BY chat ORDER BY chat", c.Upper, c.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []any{}
	more := false
	for rows.Next() {
		var chat string
		var lo, hi, count int64
		if err = rows.Scan(&chat, &lo, &hi, &count); err != nil {
			return nil, err
		}
		if !allowed(chat) {
			continue
		}
		if len(out) == q.Limit {
			more = true
			break
		}
		c.ID = chat
		out = append(out, map[string]any{"chat_id": chat, "oldest_cached_timestamp": lo, "latest_cached_timestamp": hi, "cached_messages": count})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	next := ""
	if more {
		next = s.encode(c)
	}
	return map[string]any{"chats": out, "next_cursor": next, "history_complete": false, "coverage": "locally_cached_partial"}, nil
}
