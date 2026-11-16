// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Nikita Arkhipov

package whatsmeow

import (
	"context"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// PersonalMCPContactList uses the same USync query as pinned IsOnWhatsApp.
// The caller needs the contact's explicit in/out status: IsOnWhatsApp's bool
// also becomes false for missing or unrecognized contact data. The response
// stays inside the bridge process and must never be logged or serialized.
func (cli *Client) PersonalMCPContactList(ctx context.Context, phones []string) (*waBinary.Node, error) {
	jids := make([]types.JID, len(phones))
	for i, phone := range phones {
		jids[i] = types.NewJID(phone, types.LegacyUserServer)
	}
	return cli.usync(ctx, jids, "query", "interactive", []waBinary.Node{
		{Tag: "contact", Attrs: waBinary.Attrs{"addressing_mode": "lid"}},
		{Tag: "business", Content: []waBinary.Node{{Tag: "verified_name"}}},
		{Tag: "disappearing_mode"},
		{Tag: "username"},
	})
}
