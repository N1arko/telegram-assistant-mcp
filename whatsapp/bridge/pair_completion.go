// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov
package main

import (
	"context"
	"errors"
)

type pairEvent int

const (
	pairAuthenticated pairEvent = iota
	pairReconnect
	pairRejected
)

// PairSuccess stores credentials, but the phone still needs the post-pair login.
// This only reconnects authentication; no messages are sent or retried.
func awaitPairLogin(ctx context.Context, events <-chan pairEvent, connect func(context.Context) error, valid func() bool) error {
	reconnected := false
	for {
		select {
		case <-ctx.Done():
			return errors.New("pair_login_timeout")
		case event, open := <-events:
			if !open || !valid() {
				return errors.New("pair_login_rejected")
			}
			switch event {
			case pairAuthenticated:
				return nil
			case pairRejected:
				return errors.New("pair_login_rejected")
			case pairReconnect:
				if reconnected {
					return errors.New("pair_login_reconnect_limit")
				}
				reconnected = true
				if connect(ctx) != nil {
					return errors.New("pair_login_connection_failed")
				}
			}
		}
	}
}
