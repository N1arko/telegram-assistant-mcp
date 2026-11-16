// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	signalLogger "go.mau.fi/libsignal/logger"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

const chatA = "10001@s.whatsapp.net"
const chatB = "10002@s.whatsapp.net"

type fakeWA struct {
	sent, downloads int
	connected       bool
	err             error
	media           []byte
	requests        []Request
}

func (f *fakeWA) Connected() bool { return f.connected }
func (f *fakeWA) Send(_ context.Context, q Request, id string) (Record, error) {
	f.sent++
	f.requests = append(f.requests, q)
	return Record{Text: q.Text, FromMe: true}, f.err
}
func (f *fakeWA) Download(_ context.Context, r Record) ([]byte, error) {
	f.downloads++
	return f.media, f.err
}
func fixture(t *testing.T) (*Bridge, *fakeWA) {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	s, e := openStore(filepath.Join(dir, "history.sqlite"), key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	wa := &fakeWA{connected: true}
	now := time.Unix(1800000000, 0)
	return &Bridge{cfg: Config{ReadChats: []string{chatA, chatB}, WriteChats: []string{chatA}, PerMinute: 1, PerDay: 20}, store: s, wa: wa, token: strings.Repeat("a", 64), clock: func() time.Time { return now }}, wa
}
func add(t *testing.T, b *Bridge, chat, id, text string, ts int64) {
	t.Helper()
	if e := b.store.put(chat, id, ts, Record{Text: text, Sender: chat, Raw: []byte{1, 2, 3}}); e != nil {
		t.Fatal(e)
	}
}
func sendQ() Request {
	return Request{Op: "send_text", ChatID: chatA, Text: "fixture text", RequestID: "fixture_request_0001"}
}
func errorIs(t *testing.T, v map[string]any, code string) {
	t.Helper()
	if v["error"] != code {
		t.Fatalf("expected %s, got %#v", code, v)
	}
}

func TestHistoryEncryptionAndWrongKey(t *testing.T) {
	b, _ := fixture(t)
	add(t, b, chatA, "id1", "fixture private body", 1)
	var cipher []byte
	b.store.db.QueryRow("SELECT payload FROM messages").Scan(&cipher)
	if bytes.Contains(cipher, []byte("fixture private body")) {
		t.Fatal("plaintext persisted")
	}
	cipher[len(cipher)-1] ^= 1
	if _, e := b.store.unseal(cipher, chatA+"\x00id1"); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e := b.store.unseal(cipher, chatB+"\x00id1"); e == nil {
		t.Fatal("AAD accepted")
	}
}
func TestPaginationStableAcrossBackfillAndRestart(t *testing.T) {
	b, _ := fixture(t)
	for i := 0; i < 31; i++ {
		add(t, b, chatA, fmt.Sprintf("id%03d", i), "fixture", int64(i/2))
	}
	q := Request{Op: "history", ChatID: chatA, Limit: 7}
	v, e := b.store.history(q)
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	consume := func(v map[string]any) {
		for _, raw := range v["messages"].([]any) {
			id := raw.(map[string]any)["message_id"].(string)
			if seen[id] {
				t.Fatal("duplicate")
			}
			seen[id] = true
		}
	}
	consume(v)
	q.Cursor = v["next_cursor"].(string)
	// New messages and older backfill are excluded from the original snapshot.
	add(t, b, chatA, "new", "new", 100)
	add(t, b, chatA, "backfill", "old", -100)
	var file string
	b.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&file)
	b.store.db.Close()
	s, e := openStore(file, b.store.key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	b.store = s
	for q.Cursor != "" {
		v, e = b.store.history(q)
		if e != nil {
			t.Fatal(e)
		}
		consume(v)
		q.Cursor = v["next_cursor"].(string)
	}
	if len(seen) != 31 || seen["new"] || seen["backfill"] {
		t.Fatalf("unstable snapshot: %d", len(seen))
	}
}
func TestCursorRejectsTamperDifferentChatAndQuery(t *testing.T) {
	b, _ := fixture(t)
	for i := 0; i < 3; i++ {
		add(t, b, chatA, fmt.Sprint(i), "fixture", int64(i))
	}
	q := Request{Op: "search", ChatID: chatA, Query: "fixture", Limit: 1}
	v, _ := b.store.history(q)
	q.Cursor = v["next_cursor"].(string)
	for _, variant := range []Request{{Op: "search", ChatID: chatB, Query: q.Query, Limit: 1, Cursor: q.Cursor}, {Op: "search", ChatID: chatA, Query: "other", Limit: 1, Cursor: q.Cursor}, {Op: "search", ChatID: chatA, Query: q.Query, Limit: 1, Cursor: "broken" + q.Cursor}} {
		if _, e := b.store.history(variant); e == nil {
			t.Fatal("invalid cursor accepted")
		}
	}
}
func TestEmptySearchPageHasContinuation(t *testing.T) {
	b, _ := fixture(t)
	add(t, b, chatA, "old", "Needle", 1)
	for i := 0; i < 1000; i++ {
		add(t, b, chatA, fmt.Sprintf("id%d", i), "other", int64(i+2))
	}
	q := Request{Op: "search", ChatID: chatA, Query: "needle", Limit: 20}
	v, _ := b.store.history(q)
	if len(v["messages"].([]any)) != 0 || v["next_cursor"] == "" {
		t.Fatal("scan boundary lost")
	}
	q.Cursor = v["next_cursor"].(string)
	v, _ = b.store.history(q)
	if len(v["messages"].([]any)) != 1 || v["next_cursor"] != "" {
		t.Fatal("search continuation failed")
	}
}
func TestChatAllowlistAndChatPagination(t *testing.T) {
	b, _ := fixture(t)
	add(t, b, chatA, "a", "a", 1)
	add(t, b, chatB, "b", "b", 2)
	add(t, b, "99999@s.whatsapp.net", "c", "c", 3)
	q := Request{Op: "list_chats", Limit: 1}
	v := b.call(context.Background(), q)
	if len(v["chats"].([]any)) != 1 {
		t.Fatal(v)
	}
	q.Cursor = v["next_cursor"].(string)
	v = b.call(context.Background(), q)
	if v["next_cursor"] != "" {
		t.Fatal(v)
	}
	errorIs(t, b.call(context.Background(), Request{Op: "history", ChatID: "99999@s.whatsapp.net", Limit: 1}), "chat_not_allowed")
}
func TestReadNeverDownloadsAndSelectedMediaOnly(t *testing.T) {
	b, wa := fixture(t)
	r := Record{Text: "fixture", Kind: "photo", MIME: "image/png", Filename: "photo"}
	b.store.put(chatA, "image", 1, r)
	for _, q := range []Request{{Op: "history", ChatID: chatA, Limit: 20}, {Op: "search", ChatID: chatA, Query: "fixture", Limit: 20}, {Op: "list_chats", Limit: 20}} {
		if v := b.call(context.Background(), q); v["error"] != nil {
			t.Fatal(v)
		}
	}
	if wa.downloads != 0 || wa.sent != 0 {
		t.Fatal("read side effect")
	}
	wa.media = []byte("fixture image bytes")
	v := b.call(context.Background(), Request{Op: "get_media", ChatID: chatA, MessageID: "image"})
	if v["data_base64"] != base64.StdEncoding.EncodeToString(wa.media) || wa.downloads != 1 {
		t.Fatal(v)
	}
	errorIs(t, b.call(context.Background(), Request{Op: "get_media", ChatID: chatB, MessageID: "image"}), "message_not_cached")
	wa.media = make([]byte, maxMedia+1)
	errorIs(t, b.call(context.Background(), Request{Op: "get_media", ChatID: chatA, MessageID: "image"}), "media_too_large")
}
func TestDefaultDenyScopeIndependentOfAllowlist(t *testing.T) {
	b, wa := fixture(t)
	errorIs(t, b.call(context.Background(), sendQ()), "write_disabled")
	b.cfg.WriteEnabled = true
	q := sendQ()
	q.ChatID = chatB
	errorIs(t, b.call(context.Background(), q), "write_disabled")
	if wa.sent != 0 {
		t.Fatal("send reached transport")
	}
}
func TestStableSendKeyAndConflict(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	q := sendQ()
	v := b.call(context.Background(), q)
	if v["status"] != "server_accepted" || v["delivery_receipt"] != false {
		t.Fatal(v)
	}
	v = b.call(context.Background(), q)
	if v["duplicate_request"] != true || wa.sent != 1 {
		t.Fatal(v)
	}
	q.Text = "different"
	errorIs(t, b.call(context.Background(), q), "request_id_conflict")
}
func TestUnknownNeverResentAfterRestart(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	wa.err = errors.New("synthetic transport timeout")
	q := sendQ()
	v := b.call(context.Background(), q)
	if v["status"] != "unknown" {
		t.Fatal(v)
	}
	var file string
	b.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&file)
	b.store.db.Close()
	s, e := openStore(file, b.store.key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	b.store = s
	wa.err = nil
	v = b.call(context.Background(), q)
	if v["status"] != "unknown" || wa.sent != 1 {
		t.Fatal("unknown resent")
	}
	v = b.call(context.Background(), Request{Op: "send_status", ChatID: chatA, RequestID: q.RequestID})
	if v["status"] != "unknown" || v["observed_in_local_history"] != false {
		t.Fatal(v)
	}
	add(t, b, chatA, v["message_id"].(string), "fixture readback", 1)
	v = b.call(context.Background(), Request{Op: "send_status", ChatID: chatA, RequestID: q.RequestID})
	if v["observed_in_local_history"] != true || v["status"] != "unknown" || v["delivery_receipt"] != false {
		t.Fatal(v)
	}
}
func TestCrashReservedRequestIsTerminal(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	q := sendQ()
	raw, _ := json.Marshal(q)
	sum := sha256.Sum256(raw)
	b.store.db.Exec("INSERT INTO sends VALUES(?,?,?,?,?,?)", q.RequestID, hex.EncodeToString(sum[:]), chatA, "fixedid", "unknown", b.clock().Unix())
	v := b.call(context.Background(), q)
	if v["status"] != "unknown" || wa.sent != 0 {
		t.Fatal(v)
	}
}
func TestPersistentMinuteAndDayQuotas(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	b.cfg.PerDay = 1
	q := sendQ()
	b.call(context.Background(), q)
	q.RequestID = "fixture_request_0002"
	errorIs(t, b.call(context.Background(), q), "send_quota_exceeded")
	now := b.clock().Add(61 * time.Second)
	b.clock = func() time.Time { return now }
	errorIs(t, b.call(context.Background(), q), "send_quota_exceeded")
	now = now.Add(24 * time.Hour)
	if b.call(context.Background(), q)["status"] != "server_accepted" || wa.sent != 2 {
		t.Fatal("quota expiry")
	}
}
func TestReplyPreflightAndMediaValidation(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	q := sendQ()
	q.ReplyTo = "missing"
	errorIs(t, b.call(context.Background(), q), "reply_not_cached")
	add(t, b, chatA, "reply", "fixture", 1)
	q.ReplyTo = "reply"
	if b.call(context.Background(), q)["status"] != "server_accepted" || wa.requests[0].ReplyTo != "reply" {
		t.Fatal("reply lost")
	}
	for _, q := range []Request{{Op: "send_media", ChatID: chatA, RequestID: "fixture_media_0001", Data: "broken", Kind: "photo", MIME: "image/png", Filename: "a.png"}, {Op: "send_media", ChatID: chatA, RequestID: "fixture_media_0002", Data: base64.StdEncoding.EncodeToString([]byte("%PDF-fixture")), Kind: "document", MIME: "application/pdf", Filename: "../outside"}} {
		errorIs(t, b.call(context.Background(), q), "invalid_media")
	}
}
func TestAllThreeOutboundMediaKindsAndReply(t *testing.T) {
	for _, kind := range []string{"photo", "document", "audio"} {
		t.Run(kind, func(t *testing.T) {
			b, wa := fixture(t)
			b.cfg.WriteEnabled = true
			mime := "application/pdf"
			data := []byte("%PDF-fixture")
			if kind == "photo" {
				mime = "image/png"
				data = []byte{137, 80, 78, 71, 13, 10, 26, 10}
			}
			if kind == "audio" {
				mime = "audio/ogg"
				data = []byte("OggSfixture")
			}
			q := Request{Op: "send_media", ChatID: chatA, RequestID: "fixture_media_0001", Data: base64.StdEncoding.EncodeToString(data), Kind: kind, MIME: mime, Filename: "fixture"}
			if v := b.call(context.Background(), q); v["status"] != "server_accepted" || wa.sent != 1 {
				t.Fatal(v)
			}
			b.call(context.Background(), q)
			if wa.sent != 1 {
				t.Fatal("media duplicated")
			}
		})
	}
}
func TestLoopbackAuthOriginAndUnknownRoutes(t *testing.T) {
	b, _ := fixture(t)
	for _, tc := range []struct {
		host, token, origin, path string
		code                      int
	}{{"127.0.0.1:8878", "", "", "/v1/call", 401}, {"evil.test", b.token, "", "/v1/call", 403}, {"127.0.0.1:8878", b.token, "https://evil.test", "/v1/call", 403}, {"127.0.0.1:8878", b.token, "", "/api/mark-read", 404}, {"127.0.0.1:8878", b.token, "", "/v1/call", 200}} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{"op":"status"}`))
		r.Host = tc.host
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("X-WhatsApp-Account", "default")
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		b.handler(w, r)
		if w.Code != tc.code {
			t.Fatalf("status %d", w.Code)
		}
	}
}
func TestConcurrentDuplicateRequestsSendOnce(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.WriteEnabled = true
	raw, _ := json.Marshal(sendQ())
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			r := httptest.NewRequest("POST", "/v1/call", bytes.NewReader(raw))
			r.Host = "127.0.0.1:8878"
			r.Header.Set("Authorization", "Bearer "+b.token)
			r.Header.Set("X-WhatsApp-Account", "default")
			b.handler(httptest.NewRecorder(), r)
		})
	}
	wg.Wait()
	if wa.sent != 1 {
		t.Fatalf("%d sends", wa.sent)
	}
}
func TestSessionRevocationStopsReconnectAndNoQR(t *testing.T) {
	b, _ := fixture(t)
	dir := t.TempDir()
	w := &WhatsApp{store: b.store, cfg: Config{StateDir: dir}}
	w.event(&events.LoggedOut{})
	if w.State() != "manual_relink_required" || w.Connected() {
		t.Fatal("revoked session accepted")
	}
	reconnect(context.Background(), w)
	if _, e := os.Stat(filepath.Join(dir, "revoked")); e != nil {
		t.Fatal("revocation not durable")
	}
	if backoff(0) != time.Second || backoff(20) != 64*time.Second {
		t.Fatal("invalid backoff")
	}
}
func TestEventIngestOnlyAllowedNoAutomaticMedia(t *testing.T) {
	b, wa := fixture(t)
	w := &WhatsApp{store: b.store, cfg: b.cfg}
	m := &waE2E.Message{Conversation: proto.String("fixture body")}
	w.save(chatA, "allowed", 1, m, chatA, false)
	w.save("99999@s.whatsapp.net", "denied", 1, m, chatA, false)
	if _, e := b.store.record(chatA, "allowed"); e != nil {
		t.Fatal(e)
	}
	if _, e := b.store.record("99999@s.whatsapp.net", "denied"); e == nil {
		t.Fatal("unauthorized history stored")
	}
	if wa.downloads != 0 || wa.sent != 0 {
		t.Fatal("ingestion side effect")
	}
}
func TestOwnerOnlyFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	os.WriteFile(p, []byte("fixture"), 0644)
	if _, e := privateRead(p, 64); e == nil {
		t.Fatal("world readable accepted")
	}
	os.Chmod(p, 0600)
	if _, e := privateRead(p, 64); e != nil {
		t.Fatal(e)
	}
	os.Symlink(p, filepath.Join(dir, "link"))
	if _, e := privateRead(filepath.Join(dir, "link"), 64); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Link(p, filepath.Join(dir, "hardlink"))
	if _, e := privateRead(p, 64); e == nil {
		t.Fatal("hardlink accepted")
	}
}

type fakeReconnect struct {
	valid, open bool
	calls       int
}

func (f *fakeReconnect) SessionValid() bool   { return f.valid }
func (f *fakeReconnect) ConnectionOpen() bool { return f.open }
func (f *fakeReconnect) Connect(context.Context) error {
	f.calls++
	if f.calls < 3 {
		return errors.New("synthetic disconnect")
	}
	f.open = true
	return nil
}
func TestReconnectBackoffRecoveryAndInvalidSessionStop(t *testing.T) {
	f := &fakeReconnect{valid: true}
	var delays []time.Duration
	reconnectLoop(context.Background(), f, func(_ context.Context, d time.Duration) bool { delays = append(delays, d); return len(delays) < 3 })
	if f.calls != 3 || !f.open || len(delays) != 3 || delays[0] != 2*time.Second || delays[1] != 4*time.Second || delays[2] != time.Second {
		t.Fatalf("reconnect sequence %#v", delays)
	}
	f.valid = false
	reconnectLoop(context.Background(), f, func(context.Context, time.Duration) bool { t.Fatal("invalid session retried"); return false })
	if f.calls != 3 {
		t.Fatal("invalid session connected")
	}
	f.valid = true
	f.open = false
	reconnectLoop(context.Background(), f, func(context.Context, time.Duration) bool { return false })
	if f.calls != 4 {
		t.Fatal("disconnect not recovered")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSelectedDownloadIsBoundedBeforeSDKAllocation(t *testing.T) {
	var body = bytes.NewReader(make([]byte, maxMedia+4096))
	transport := cappedTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Body: io.NopCloser(body)}, nil
	})}
	req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), attachmentKey{}, true), "GET", "https://fixture.invalid", nil)
	resp, e := transport.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e == nil || len(data) > maxMedia+1024 {
		t.Fatal("unbounded media read")
	}
}
func TestQRRendererNeverPrintsRawPayload(t *testing.T) {
	var out bytes.Buffer
	payload := "fixture-qr-payload-for-unit-test"
	if e := renderQR(&out, payload); e != nil {
		t.Fatal(e)
	}
	s := out.String()
	if strings.Contains(s, payload) || !strings.ContainsAny(s, "█▀▄") || !strings.HasPrefix(s, "\x1b[30;47m") {
		t.Fatal("invalid private QR renderer")
	}
}
func TestConfigRequiresEncryptionAttestationAndExactPrivatePaths(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	c := Config{StateDir: dir, KeyFile: filepath.Join(dir, "history.key"), TokenFile: filepath.Join(dir, "bridge.token"), ReadChats: []string{chatA}, PerMinute: 1, PerDay: 20, EncryptedVolumeConfirmed: true}
	path := filepath.Join(dir, "config.json")
	write := func() { b, _ := json.Marshal(c); os.WriteFile(path, b, 0600) }
	write()
	if _, e = loadConfig(path); e != nil {
		t.Fatal(e)
	}
	c.EncryptedVolumeConfirmed = false
	write()
	if _, e = loadConfig(path); e == nil {
		t.Fatal("unencrypted storage accepted")
	}
	c.EncryptedVolumeConfirmed = true
	c.KeyFile = "/outside/history.key"
	write()
	if _, e = loadConfig(path); e == nil {
		t.Fatal("external key path accepted")
	}
}

func TestSignalLibraryLoggingIsExplicitlyDisabled(t *testing.T) {
	silenceLibraries()
	if _, ok := signalLogger.Logger.(signalNoop); !ok {
		t.Fatal("signal default logger remains enabled")
	}
}
