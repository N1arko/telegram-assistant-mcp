// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

type WhatsApp struct {
	client        *whatsmeow.Client
	store         *Store
	cfg           Config
	revoked       atomic.Bool
	storageFailed atomic.Bool
}

type attachmentKey struct{}
type cappedTransport struct{ base http.RoundTripper }
type cappedBody struct {
	io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errors.New("media_too_large")
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, e := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, e
}
func (t cappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, e := t.base.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	if r.Context().Value(attachmentKey{}) == true {
		const cap = int64(maxMedia + 1024)
		if resp.ContentLength > cap {
			resp.Body.Close()
			return nil, errors.New("media_too_large")
		}
		resp.Body = &cappedBody{ReadCloser: resp.Body, left: cap}
	}
	return resp, nil
}

func (w *WhatsApp) Connected() bool {
	return !w.revoked.Load() && !w.storageFailed.Load() && w.client.IsConnected() && w.client.IsLoggedIn()
}
func (w *WhatsApp) State() string {
	if w.revoked.Load() {
		return "manual_relink_required"
	}
	if w.storageFailed.Load() {
		return "storage_error"
	}
	if w.Connected() {
		return "connected"
	}
	return "disconnected"
}
func sanitizeName(s string) string {
	s = filepath.Base(strings.ReplaceAll(s, "\\", "/"))
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		return "attachment"
	}
	return s
}
func makeRecord(m *waE2E.Message, sender string, fromMe bool) Record {
	r := Record{Sender: sender, FromMe: fromMe}
	if m == nil {
		return r
	}
	r.Text = m.GetConversation()
	if x := m.GetExtendedTextMessage(); x != nil {
		r.Text = x.GetText()
	}
	if x := m.GetImageMessage(); x != nil {
		r.Kind = "photo"
		r.Text = x.GetCaption()
		r.MIME = x.GetMimetype()
		r.Filename = "photo"
	}
	if x := m.GetDocumentMessage(); x != nil {
		r.Kind = "document"
		r.Text = x.GetCaption()
		r.MIME = x.GetMimetype()
		r.Filename = sanitizeName(x.GetFileName())
	}
	if x := m.GetAudioMessage(); x != nil {
		r.Kind = "audio"
		r.MIME = x.GetMimetype()
		r.Filename = "audio"
	}
	// Unsupported content stays a metadata-only row. No automatic downloads.
	r.Raw, _ = proto.Marshal(m)
	return r
}
func (w *WhatsApp) save(chat, id string, ts int64, m *waE2E.Message, sender string, fromMe bool) {
	if w.revoked.Load() || !w.cfg.canRead(chat) || !idPattern.MatchString(id) || m == nil || proto.Size(m) > 1024*1024 {
		return
	}
	// View-once and expiring envelopes are deliberately excluded from the cache.
	if m.GetViewOnceMessage() != nil || m.GetViewOnceMessageV2() != nil || m.GetViewOnceMessageV2Extension() != nil || m.GetEphemeralMessage() != nil || m.GetProtocolMessage() != nil {
		return
	}
	if e := w.store.put(chat, id, ts, makeRecord(m, sender, fromMe)); e != nil {
		w.storageFailed.Store(true)
	}
}
func (w *WhatsApp) event(evt any) {
	if _, ok := evt.(events.PermanentDisconnect); ok {
		w.revoked.Store(true)
		_ = writeRevoked(w.cfg.StateDir)
		return
	}
	switch v := evt.(type) {
	case *events.PairSuccess:
		if w.cfg.ExpectedAccountJID != "" && v.ID.ToNonAD().String() != w.cfg.ExpectedAccountJID {
			w.revoked.Store(true)
			_ = writeRevoked(w.cfg.StateDir)
		}
	case *events.Message:
		if v.IsViewOnce || v.IsEphemeral {
			return
		}
		w.save(v.Info.Chat.String(), v.Info.ID, v.Info.Timestamp.Unix(), v.Message, v.Info.Sender.String(), v.Info.IsFromMe)
	case *events.HistorySync:
		// The SDK supplies history chunks. Each row commits independently and is
		// deduplicated; tool cursors are persistent snapshots across these chunks.
		for _, c := range v.Data.GetConversations() {
			chat := c.GetID()
			if !w.cfg.canRead(chat) {
				continue
			}
			for _, hm := range c.GetMessages() {
				m := hm.GetMessage()
				if m == nil {
					continue
				}
				key := m.GetKey()
				sender := key.GetParticipant()
				if sender == "" {
					sender = chat
				}
				if key.GetFromMe() && w.client.Store.ID != nil {
					sender = w.client.Store.ID.ToNonAD().String()
				}
				w.save(chat, key.GetID(), int64(m.GetMessageTimestamp()), m.GetMessage(), sender, key.GetFromMe())
			}
		}
		if _, e := w.store.db.Exec("INSERT OR REPLACE INTO sync_chunks VALUES(?,?,?)", v.Data.GetSyncType().String(), v.Data.GetChunkOrder(), v.Data.GetProgress()); e != nil {
			w.storageFailed.Store(true)
		}
	case *events.LoggedOut:
		w.revoked.Store(true)
		_ = writeRevoked(w.cfg.StateDir)
	case *events.StreamReplaced:
		// Another companion process must be resolved by the owner.
		w.revoked.Store(true)
		_ = writeRevoked(w.cfg.StateDir)
	}
}
func (w *WhatsApp) Download(ctx context.Context, r Record) ([]byte, error) {
	if !w.Connected() {
		return nil, errors.New("session_unavailable")
	}
	var m waE2E.Message
	if proto.Unmarshal(r.Raw, &m) != nil {
		return nil, errors.New("media_unavailable")
	}
	var d whatsmeow.DownloadableMessage
	switch r.Kind {
	case "photo":
		d = m.GetImageMessage()
	case "document":
		d = m.GetDocumentMessage()
	case "audio":
		d = m.GetAudioMessage()
	default:
		return nil, errors.New("unsupported_media")
	}
	sized, ok := d.(interface{ GetFileLength() uint64 })
	if !ok || sized.GetFileLength() == 0 || sized.GetFileLength() > maxMedia {
		return nil, errors.New("media_too_large")
	}
	return w.client.Download(context.WithValue(ctx, attachmentKey{}, true), d)
}
func (w *WhatsApp) Send(ctx context.Context, q Request, id string) (Record, error) {
	var m *waE2E.Message
	info := &waE2E.ContextInfo{}
	if q.ReplyTo != "" {
		r, e := w.store.record(q.ChatID, q.ReplyTo)
		if e != nil {
			return Record{}, e
		}
		quoted := &waE2E.Message{}
		if proto.Unmarshal(r.Raw, quoted) != nil {
			return Record{}, errors.New("reply_unavailable")
		}
		info.StanzaID = proto.String(q.ReplyTo)
		info.Participant = proto.String(r.Sender)
		info.QuotedMessage = quoted
	}
	if q.Op == "send_text" {
		m = &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String(q.Text), ContextInfo: info}}
	} else {
		data, e := base64.StdEncoding.Strict().DecodeString(q.Data)
		if e != nil {
			return Record{}, e
		}
		mt := whatsmeow.MediaDocument
		if q.Kind == "photo" {
			mt = whatsmeow.MediaImage
		}
		if q.Kind == "audio" {
			mt = whatsmeow.MediaAudio
		}
		u, e := w.client.Upload(ctx, data, mt)
		if e != nil {
			return Record{}, e
		}
		switch q.Kind {
		case "photo":
			m = &waE2E.Message{ImageMessage: &waE2E.ImageMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileEncSHA256: u.FileEncSHA256, FileSHA256: u.FileSHA256, FileLength: &u.FileLength, Mimetype: &q.MIME, Caption: &q.Text, ContextInfo: info}}
		case "audio":
			m = &waE2E.Message{AudioMessage: &waE2E.AudioMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileEncSHA256: u.FileEncSHA256, FileSHA256: u.FileSHA256, FileLength: &u.FileLength, Mimetype: &q.MIME, ContextInfo: info}}
		case "document":
			m = &waE2E.Message{DocumentMessage: &waE2E.DocumentMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileEncSHA256: u.FileEncSHA256, FileSHA256: u.FileSHA256, FileLength: &u.FileLength, Mimetype: &q.MIME, FileName: &q.Filename, Caption: &q.Text, ContextInfo: info}}
		default:
			return Record{}, errors.New("invalid_media")
		}
	}
	target, e := types.ParseJID(q.ChatID)
	if e != nil {
		return Record{}, e
	}
	_, e = w.client.SendMessage(ctx, target, m, whatsmeow.SendRequestExtra{ID: id, Timeout: 0})
	sender := ""
	if w.client.Store.ID != nil {
		sender = w.client.Store.ID.ToNonAD().String()
	}
	return makeRecord(m, sender, true), e
}
