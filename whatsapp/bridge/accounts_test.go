// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0700)
	return p
}

func TestNamedStateCannotBeReusedByAnotherAccount(t *testing.T) {
	personal, work := privateTemp(t), privateTemp(t)
	if e := initializeState(personal, "personal"); e != nil {
		t.Fatal(e)
	}
	if e := initializeState(work, "work"); e != nil {
		t.Fatal(e)
	}
	if e := verifyAccountState(Config{AccountID: "personal", StateDir: personal}); e != nil {
		t.Fatal(e)
	}
	if e := verifyAccountState(Config{AccountID: "work", StateDir: personal}); e == nil {
		t.Fatal("foreign account state accepted")
	}
	for _, name := range []string{"history.key", "bridge.token"} {
		a, _ := privateRead(filepath.Join(personal, name), 64)
		b, _ := privateRead(filepath.Join(work, name), 64)
		if bytes.Equal(a, b) {
			t.Fatal("generated shared secret")
		}
	}
	if e := initializeState(personal, "work"); e == nil {
		t.Fatal("existing state overwritten")
	}
	if _, e := os.Stat(filepath.Join(personal, "session.db")); !os.IsNotExist(e) {
		t.Fatal("binding verification created session")
	}
}

func TestLegacyDefaultStateIsNotAdoptedAsNamedAccount(t *testing.T) {
	dir := privateTemp(t)
	if e := verifyAccountState(Config{StateDir: dir}); e != nil {
		t.Fatal(e)
	}
	if e := verifyAccountState(Config{AccountID: "work", StateDir: dir}); e == nil {
		t.Fatal("legacy state silently adopted")
	}
}

func TestBridgeRejectsCrossAccountHeadersTokensAndPortsBeforeSend(t *testing.T) {
	b, wa := fixture(t)
	b.cfg.AccountID = "work"
	b.cfg.ListenPort = 8888
	b.cfg.WriteEnabled = true
	b.token = strings.Repeat("b", 64)
	body, _ := json.Marshal(sendQ())
	for _, tc := range []struct {
		account, token, host string
		status               int
	}{{"personal", b.token, "127.0.0.1:8888", 409}, {"work", strings.Repeat("a", 64), "127.0.0.1:8888", 401}, {"work", b.token, "127.0.0.1:8878", 403}} {
		r := httptest.NewRequest("POST", "/v1/call", bytes.NewReader(body))
		r.Host = tc.host
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("X-WhatsApp-Account", tc.account)
		out := httptest.NewRecorder()
		b.handler(out, r)
		if out.Code != tc.status {
			t.Fatalf("status %d expected %d", out.Code, tc.status)
		}
	}
	if wa.sent != 0 {
		t.Fatal("cross account request sent")
	}
}

func TestAccountHistoryCursorsPermissionsAndQuotasAreSeparate(t *testing.T) {
	a, wa := fixture(t)
	b, wb := fixture(t)
	a.cfg.AccountID = "personal"
	b.cfg.AccountID = "work"
	var file string
	b.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&file)
	b.store.db.Close()
	separate, e := openStore(file, bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer separate.db.Close()
	b.store = separate
	add(t, a, chatA, "id1", "personal fixture", 1)
	add(t, a, chatA, "id2", "personal fixture", 2)
	add(t, b, chatA, "id1", "work fixture", 1)
	q := Request{Op: "history", ChatID: chatA, Limit: 1}
	page, e := a.store.history(q)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = page["next_cursor"].(string)
	if _, e = b.store.history(q); e == nil {
		t.Fatal("foreign account cursor accepted")
	}
	q.Cursor = ""
	page, _ = b.store.history(q)
	if page["messages"].([]any)[0].(map[string]any)["text"] != "work fixture" {
		t.Fatal("history mixed")
	}
	a.cfg.WriteEnabled = true
	a.cfg.PerDay = 1
	send := sendQ()
	if a.call(context.Background(), send)["status"] != "server_accepted" {
		t.Fatal("personal send failed")
	}
	errorIs(t, b.call(context.Background(), send), "write_disabled")
	b.cfg.WriteEnabled = true
	if b.call(context.Background(), send)["status"] != "server_accepted" {
		t.Fatal("foreign quota or request journal affected work")
	}
	send.RequestID = "fixture_request_0002"
	errorIs(t, a.call(context.Background(), send), "send_quota_exceeded")
	if wa.sent != 1 || wb.sent != 1 {
		t.Fatal("wrong transport")
	}
	b.cfg.ReadChats = []string{chatB}
	errorIs(t, b.call(context.Background(), Request{Op: "history", ChatID: chatA, Limit: 1}), "chat_not_allowed")
}

func TestWrongPhonePairIsQuarantinedWithoutAffectingOtherAccount(t *testing.T) {
	a, _ := fixture(t)
	b, _ := fixture(t)
	adir, bdir := privateTemp(t), privateTemp(t)
	personal := &WhatsApp{store: a.store, cfg: Config{AccountID: "personal", StateDir: adir, ExpectedAccountJID: "10001@s.whatsapp.net", ReadChats: []string{chatA}}}
	work := &WhatsApp{store: b.store, cfg: Config{AccountID: "work", StateDir: bdir, ExpectedAccountJID: "10002@s.whatsapp.net"}}
	personal.event(&events.PairSuccess{ID: types.NewJID("10002", types.DefaultUserServer)})
	if !personal.revoked.Load() || work.revoked.Load() {
		t.Fatal("wrong isolation during quarantine")
	}
	personal.save(chatA, "later", 1, &waE2E.Message{Conversation: proto.String("fixture")}, chatA, false)
	if _, e := a.store.record(chatA, "later"); e == nil {
		t.Fatal("wrong phone history persisted")
	}
	if _, e := os.Stat(filepath.Join(adir, "revoked")); e != nil {
		t.Fatal("quarantine not durable")
	}
	if _, e := os.Stat(filepath.Join(bdir, "revoked")); !os.IsNotExist(e) {
		t.Fatal("other session revoked")
	}
}
