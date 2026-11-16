// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

type lookupFake struct {
	*fakeWA
	lookups  int
	override bool
	results  []Recipient
	err      error
}

func (f *lookupFake) Resolve(_ context.Context, phones []string) ([]Recipient, error) {
	f.lookups++
	if f.override {
		return f.results, f.err
	}
	out := []Recipient{}
	for i, p := range phones {
		out = append(out, knownRecipient(p, lookupRegistered, fmt.Sprintf("100%02d@lid", i)))
	}
	return out, nil
}

func lookupUser(query, status, jid, pn string) waBinary.Node {
	attrs := waBinary.Attrs{}
	if jid != "" {
		attrs["jid"], _ = types.ParseJID(jid)
	}
	if pn != "" {
		attrs["pn_jid"], _ = types.ParseJID(pn)
	}
	return waBinary.Node{Tag: "user", Attrs: attrs, Content: []waBinary.Node{
		{Tag: "contact", Attrs: waBinary.Attrs{"type": status}, Content: []byte(query)},
	}}
}

func TestUSyncRegistrationEvidence(t *testing.T) {
	const phone = "+10001"
	valid := lookupUser(phone+"@c.us", "in", "70001@lid", "10009@s.whatsapp.net")
	missingContact := waBinary.Node{Tag: "user", Attrs: waBinary.Attrs{"pn_jid": types.NewJID("10001", types.DefaultUserServer)}}
	userError := lookupUser(phone, "out", "", "")
	userError.Content = append(userError.GetChildren(), waBinary.Node{Tag: "error", Attrs: waBinary.Attrs{"text": "private-error-fixture"}})
	contactError := lookupUser(phone, "out", "", "")
	contactError.GetChildren()[0].Attrs["error"] = "private-contact-error-fixture"
	duplicateContact := lookupUser(phone, "out", "", "")
	duplicateContact.Content = append(duplicateContact.GetChildren(), waBinary.Node{Tag: "contact", Attrs: waBinary.Attrs{"type": "in"}, Content: []byte(phone)})
	badJID := lookupUser(phone, "out", "", "")
	badJID.Attrs["jid"] = "private-invalid-jid-fixture"
	privacy := valid
	privacy.Content = append(privacy.GetChildren(), waBinary.Node{Tag: "business", Content: []byte("private-business-fixture")})
	cases := []struct {
		name                 string
		rows                 []waBinary.Node
		status, reason, chat string
	}{
		{"explicit_in_canonical_pn_differs", []waBinary.Node{valid}, lookupRegistered, "", "70001@lid"},
		{"explicit_out_without_jid", []waBinary.Node{lookupUser(phone, "out", "", "")}, lookupNotRegistered, "", ""},
		{"missing_row", nil, lookupUnknown, "missing_result", ""},
		{"other_query", []waBinary.Node{lookupUser("+10002", "out", "", "")}, lookupUnknown, "missing_result", ""},
		{"no_contact", []waBinary.Node{missingContact}, lookupUnknown, "incomplete_result", ""},
		{"no_status", []waBinary.Node{lookupUser(phone, "", "", "")}, lookupUnknown, "unrecognized_status", ""},
		{"unknown_status", []waBinary.Node{lookupUser(phone, "pending", "", "")}, lookupUnknown, "unrecognized_status", ""},
		{"in_without_jid", []waBinary.Node{lookupUser(phone, "in", "", "")}, lookupUnknown, "incomplete_result", ""},
		{"missing_query", []waBinary.Node{lookupUser("", "out", "", "10001@s.whatsapp.net")}, lookupUnknown, "incomplete_result", ""},
		{"mismatched_query", []waBinary.Node{lookupUser("+10002", "out", "", "10001@s.whatsapp.net")}, lookupUnknown, "query_mismatch", ""},
		{"group_is_not_recipient", []waBinary.Node{lookupUser(phone, "in", "10001@g.us", "")}, lookupUnknown, "incomplete_result", ""},
		{"malformed_jid_with_out", []waBinary.Node{badJID}, lookupUnknown, "incomplete_result", ""},
		{"user_error", []waBinary.Node{userError}, lookupUnknown, "lookup_error", ""},
		{"contact_error", []waBinary.Node{contactError}, lookupUnknown, "lookup_error", ""},
		{"duplicate_contact", []waBinary.Node{duplicateContact}, lookupUnknown, "incomplete_result", ""},
		{"conflicting_rows", []waBinary.Node{valid, lookupUser(phone, "out", "", "")}, lookupUnknown, "duplicate_result", ""},
		{"identical_duplicate_rows", []waBinary.Node{valid, valid}, lookupUnknown, "duplicate_result", ""},
		{"private_fields_omitted", []waBinary.Node{privacy}, lookupRegistered, "", "70001@lid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := waBinary.Node{Tag: "list", Content: tc.rows}
			out := parseContactList([]string{phone}, &list)
			if len(out) != 1 {
				t.Fatal("wrong recipient count")
			}
			r := out[0]
			if r.LookupStatus != tc.status || r.Reason != tc.reason || r.ChatID != tc.chat {
				t.Fatalf("wrong outcome: status=%s reason=%s", r.LookupStatus, r.Reason)
			}
			if tc.status == lookupUnknown {
				if r.Registered != nil {
					t.Fatal("unknown registration became a bool")
				}
			} else if r.Registered == nil || *r.Registered != (tc.status == lookupRegistered) {
				t.Fatal("wrong confirmed registration")
			}
			data, err := json.Marshal(out)
			if err != nil || strings.Contains(string(data), "private-") || strings.Contains(string(data), "10009") {
				t.Fatal("private response fields leaked")
			}
			if tc.status == lookupUnknown && !strings.Contains(string(data), `"registered":null`) {
				t.Fatal("unknown did not serialize as null")
			}
		})
	}
}

func TestUSyncPartialBatchAndQueryCorrelation(t *testing.T) {
	phones := []string{"+10001", "+10002", "+10003"}
	list := waBinary.Node{Tag: "list", Content: []waBinary.Node{
		lookupUser("+10003", "out", "", ""),
		lookupUser("10001@c.us", "in", "70001@lid", "10009@s.whatsapp.net"),
	}}
	out := parseContactList(phones, &list)
	if out[0].LookupStatus != lookupRegistered || out[0].ChatID != "70001@lid" || out[0].phoneJID.User != "10009" || out[1].LookupStatus != lookupUnknown || out[2].LookupStatus != lookupNotRegistered {
		t.Fatal("partial batch or canonical correlation failed")
	}
	if lookupResult(out)["lookup_complete"] != false {
		t.Fatal("partial batch reported complete")
	}
}

func TestUSyncInvalidEnvelopes(t *testing.T) {
	for _, list := range []*waBinary.Node{nil, {Tag: "unexpected"}, {Tag: "list", Content: []byte("private-body-fixture")}, {Tag: "list", Content: []waBinary.Node{{Tag: "error"}}}} {
		out := parseContactList([]string{"+10001"}, list)
		if len(out) != 1 || out[0].LookupStatus != lookupUnknown || out[0].Registered != nil || out[0].ChatID != "" {
			t.Fatal("invalid envelope became registration evidence")
		}
	}
}

func TestBridgeLookupMissingIncompleteAndErrorsStayUnknown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rows     []Recipient
		err      error
		statuses []string
	}{
		{"empty", nil, nil, []string{lookupUnknown, lookupUnknown}},
		{"partial", []Recipient{knownRecipient("+10002", lookupNotRegistered, "")}, nil, []string{lookupUnknown, lookupNotRegistered}},
		{"untyped_false", []Recipient{{PhoneNumber: "+10001"}}, nil, []string{lookupUnknown, lookupUnknown}},
		{"bad_positive", []Recipient{knownRecipient("+10001", lookupRegistered, "")}, nil, []string{lookupUnknown, lookupUnknown}},
		{"duplicate", []Recipient{knownRecipient("+10001", lookupNotRegistered, ""), knownRecipient("+10001", lookupRegistered, "70001@lid")}, nil, []string{lookupUnknown, lookupUnknown}},
		{"rpc_error", []Recipient{knownRecipient("+10001", lookupNotRegistered, "")}, errors.New("private-error-fixture"), []string{lookupUnknown, lookupUnknown}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, wa := fixture(t)
			b.cfg.ReadAccess = "all_chats"
			b.wa = &lookupFake{fakeWA: wa, override: true, results: tc.rows, err: tc.err}
			result := b.resolve(context.Background(), []string{"+10001", "10002", "+10001"})
			out, ok := result["recipients"].([]Recipient)
			if !ok || len(out) != 2 || result["lookup_complete"] != false {
				t.Fatal("missing unknown results")
			}
			for i, r := range out {
				if r.LookupStatus != tc.statuses[i] || r.LookupStatus == lookupUnknown && (r.Registered != nil || r.ChatID != "") {
					t.Fatal("unknown converted to registration")
				}
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "private-") {
				t.Fatal("private error leaked")
			}
			if wa.sent != 0 {
				t.Fatal("lookup sent a message")
			}
		})
	}
}
func TestOutreachToTenNewRecipientsWithoutPrelisting(t *testing.T) {
	b, wa := fixture(t)
	fake := &lookupFake{fakeWA: wa}
	b.wa = fake
	b.cfg.ReadAccess = "all_chats"
	b.cfg.WriteAccess = "all_chats"
	b.cfg.WriteEnabled = true
	b.cfg.PerMinute = 10
	b.cfg.PerDay = 200
	phones := []string{}
	for i := 0; i < 10; i++ {
		phones = append(phones, fmt.Sprintf("+100%02d", i))
	}
	result := b.call(context.Background(), Request{Op: "resolve_recipients", PhoneNumbers: phones})
	if result["error"] != nil {
		t.Fatal(result)
	}
	recipients := result["recipients"].([]Recipient)
	if len(recipients) != 10 || fake.lookups != 1 || wa.sent != 0 {
		t.Fatal("lookup sent a message")
	}
	for i, r := range recipients {
		v := b.call(context.Background(), Request{Op: "send_text", ChatID: r.ChatID, Text: "synthetic clinic outreach", RequestID: fmt.Sprintf("clinic_request_%04d", i)})
		if v["status"] != "server_accepted" {
			t.Fatal(v)
		}
	}
	if wa.sent != 10 {
		t.Fatal("batch blocked or duplicated")
	}
	v := b.call(context.Background(), Request{Op: "send_text", ChatID: recipients[0].ChatID, Text: "synthetic clinic outreach", RequestID: "clinic_request_0000"})
	if v["duplicate_request"] != true || wa.sent != 10 {
		t.Fatal("outreach duplicated")
	}
}
func TestBroadModeStillNeedsWriteAndRejectsStatusOrBroadcast(t *testing.T) {
	b, _ := fixture(t)
	b.cfg.ReadAccess = "all_chats"
	b.cfg.WriteAccess = "all_chats"
	errorIs(t, b.call(context.Background(), sendQ()), "write_disabled")
	b.cfg.WriteEnabled = true
	for _, chat := range []string{"status@broadcast", "123@newsletter", "invalid"} {
		q := sendQ()
		q.ChatID = chat
		errorIs(t, b.call(context.Background(), q), "chat_not_allowed")
	}
}
func TestRecipientLookupHonorsLegacyPolicyAndBounds(t *testing.T) {
	b, wa := fixture(t)
	fake := &lookupFake{fakeWA: wa}
	b.wa = fake
	errorIs(t, b.call(context.Background(), Request{Op: "resolve_recipients", PhoneNumbers: []string{"+99999"}}), "chat_not_allowed")
	for _, phones := range [][]string{{}, {"https://example.test"}, make([]string, 21)} {
		errorIs(t, b.call(context.Background(), Request{Op: "resolve_recipients", PhoneNumbers: phones}), "invalid_phone_numbers")
	}
	if fake.lookups != 0 || wa.sent != 0 {
		t.Fatal("invalid lookup reached network")
	}
}
