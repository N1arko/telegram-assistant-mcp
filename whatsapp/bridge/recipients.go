// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov
package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

type Recipient struct {
	PhoneNumber  string `json:"phone_number"`
	ChatID       string `json:"chat_id"`
	Registered   *bool  `json:"registered"`
	LookupStatus string `json:"lookup_status"`
	Reason       string `json:"reason,omitempty"`
	phoneJID     types.JID
}

var phonePattern = regexp.MustCompile(`^\+?[0-9]{5,20}$`)
var recipientJIDPattern = regexp.MustCompile(`^[0-9]{1,20}@(s\.whatsapp\.net|lid)$`)

const (
	lookupRegistered    = "registered"
	lookupNotRegistered = "not_registered"
	lookupUnknown       = "unknown"
)

func unknownRecipient(phone, reason string) Recipient {
	return Recipient{PhoneNumber: phone, LookupStatus: lookupUnknown, Reason: reason}
}

func knownRecipient(phone, status, chat string) Recipient {
	registered := status == lookupRegistered
	return Recipient{PhoneNumber: phone, ChatID: chat, Registered: &registered, LookupStatus: status}
}

func unknownRecipients(phones []string, reason string) []Recipient {
	out := make([]Recipient, len(phones))
	for i, phone := range phones {
		out[i] = unknownRecipient(phone, reason)
	}
	return out
}

func lookupResult(recipients []Recipient) map[string]any {
	complete := true
	for _, r := range recipients {
		complete = complete && r.LookupStatus != lookupUnknown
	}
	return map[string]any{"recipients": recipients, "lookup_complete": complete}
}

func sanitizeRecipient(r Recipient, phone string) Recipient {
	switch r.LookupStatus {
	case lookupRegistered:
		if r.Registered != nil && *r.Registered && recipientJIDPattern.MatchString(r.ChatID) {
			return knownRecipient(phone, lookupRegistered, r.ChatID)
		}
	case lookupNotRegistered:
		if r.Registered != nil && !*r.Registered && r.ChatID == "" {
			return knownRecipient(phone, lookupNotRegistered, "")
		}
	case lookupUnknown:
		switch r.Reason {
		case "missing_result", "invalid_response", "incomplete_result", "query_mismatch", "lookup_error", "unrecognized_status", "duplicate_result", "lookup_unavailable":
			return unknownRecipient(phone, r.Reason)
		}
	}
	return unknownRecipient(phone, "incomplete_result")
}

func (b *Bridge) resolve(ctx context.Context, phones []string) map[string]any {
	if len(phones) < 1 || len(phones) > 20 {
		return fail("invalid_phone_numbers")
	}
	seen := map[string]bool{}
	normalized := []string{}
	for _, phone := range phones {
		if !phonePattern.MatchString(phone) {
			return fail("invalid_phone_numbers")
		}
		digits := strings.TrimPrefix(phone, "+")
		if !b.cfg.canRead(digits + "@s.whatsapp.net") {
			return fail("chat_not_allowed")
		}
		if !seen[digits] {
			seen[digits] = true
			normalized = append(normalized, "+"+digits)
		}
	}
	if !b.wa.Connected() {
		return fail("session_unavailable")
	}
	resolver, ok := b.wa.(interface {
		Resolve(context.Context, []string) ([]Recipient, error)
	})
	if !ok {
		return fail("lookup_unavailable")
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	recipients, e := resolver.Resolve(short, normalized)
	if e != nil {
		return lookupResult(unknownRecipients(normalized, "lookup_unavailable"))
	}
	out := unknownRecipients(normalized, "missing_result")
	index := map[string]int{}
	for i, phone := range normalized {
		index[strings.TrimPrefix(phone, "+")] = i
	}
	returned := map[int]bool{}
	for _, raw := range recipients {
		i, ok := index[strings.TrimPrefix(raw.PhoneNumber, "+")]
		if !ok || !phonePattern.MatchString(raw.PhoneNumber) {
			return fail("invalid_lookup_response")
		}
		if returned[i] {
			out[i] = unknownRecipient(normalized[i], "duplicate_result")
			continue
		}
		returned[i] = true
		r := sanitizeRecipient(raw, normalized[i])
		if r.LookupStatus == lookupRegistered && !b.cfg.canRead(r.ChatID) {
			pn := strings.TrimPrefix(r.PhoneNumber, "+") + "@s.whatsapp.net"
			if b.cfg.canRead(pn) {
				r.ChatID = pn
			} else {
				return fail("chat_not_allowed")
			}
		}
		out[i] = r
	}
	return lookupResult(out)
}
func (w *WhatsApp) Resolve(ctx context.Context, phones []string) ([]Recipient, error) {
	if !w.Connected() {
		return nil, errors.New("session_unavailable")
	}
	list, e := w.client.PersonalMCPContactList(ctx, phones)
	if e != nil {
		return nil, e
	}
	out := parseContactList(phones, list)
	mappings := []store.LIDMapping{}
	for _, r := range out {
		if r.LookupStatus == lookupRegistered && strings.HasSuffix(r.ChatID, "@lid") && r.phoneJID.Server == types.DefaultUserServer {
			jid, _ := types.ParseJID(r.ChatID)
			mappings = append(mappings, store.LIDMapping{LID: jid, PN: r.phoneJID})
		}
	}
	if len(mappings) > 0 {
		if e = w.client.Store.LIDs.PutManyLIDMappings(ctx, mappings); e != nil {
			return nil, errors.New("lookup_unavailable")
		}
	}
	return out, nil
}
