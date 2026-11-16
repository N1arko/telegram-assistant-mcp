// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov
package main

import (
	"strings"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func contactQuery(node waBinary.Node) string {
	var query string
	switch value := node.Content.(type) {
	case []byte:
		query = string(value)
	case string:
		query = value
	}
	query = strings.TrimSuffix(query, "@"+types.LegacyUserServer)
	if !phonePattern.MatchString(query) {
		return ""
	}
	return strings.TrimPrefix(query, "+")
}

func parseContactList(phones []string, list *waBinary.Node) []Recipient {
	out := unknownRecipients(phones, "missing_result")
	if list == nil || list.Tag != "list" {
		return unknownRecipients(phones, "invalid_response")
	}
	if list.Content != nil {
		if _, ok := list.Content.([]waBinary.Node); !ok {
			return unknownRecipients(phones, "invalid_response")
		}
	}
	if _, ok := list.GetOptionalChildByTag("error"); ok || list.Attrs["error"] != nil {
		return unknownRecipients(phones, "lookup_error")
	}
	index := map[string]int{}
	for i, phone := range phones {
		index[strings.TrimPrefix(phone, "+")] = i
	}
	seen := map[int]bool{}
	for _, row := range list.GetChildren() {
		if row.Tag != "user" {
			continue
		}
		ag := row.AttrGetter()
		jid := ag.OptionalJIDOrEmpty("jid").ToNonAD()
		pn := ag.OptionalJIDOrEmpty("pn_jid").ToNonAD()
		contacts := row.GetChildrenByTag("contact")
		query := ""
		if len(contacts) > 0 {
			query = contactQuery(contacts[0])
		}
		// The echoed query identifies the request. A canonical PN can differ
		// (including Brazilian numbering); it must not replace a matching query.
		i, matched := index[query]
		if !matched {
			for _, candidate := range []types.JID{pn, jid} {
				if candidate.Server == types.DefaultUserServer {
					if n, ok := index[candidate.User]; ok {
						i, matched = n, true
						break
					}
				}
			}
		}
		if !matched {
			continue
		}
		if seen[i] {
			out[i] = unknownRecipient(phones[i], "duplicate_result")
			continue
		}
		seen[i] = true
		r := unknownRecipient(phones[i], "incomplete_result")
		_, userError := row.GetOptionalChildByTag("error")
		if userError || row.Attrs["error"] != nil {
			r.Reason = "lookup_error"
		} else if !ag.OK() || len(contacts) != 1 || query == "" {
			// A missing contact or query is not evidence of non-registration.
		} else if query != strings.TrimPrefix(phones[i], "+") {
			r.Reason = "query_mismatch"
		} else if _, failed := contacts[0].GetOptionalChildByTag("error"); failed || contacts[0].Attrs["error"] != nil {
			r.Reason = "lookup_error"
		} else {
			contactType, _ := contacts[0].Attrs["type"].(string)
			switch contactType {
			case "out":
				r = knownRecipient(phones[i], lookupNotRegistered, "")
			case "in":
				if jid.IsEmpty() {
					jid = pn
				}
				if recipientJIDPattern.MatchString(jid.String()) {
					r = knownRecipient(phones[i], lookupRegistered, jid.String())
					r.phoneJID = pn
				}
			default:
				r.Reason = "unrecognized_status"
			}
		}
		out[i] = r
	}
	return out
}
