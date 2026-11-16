// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov
package main

import (
	"context"
	"errors"
	"testing"
)

func TestPairWaitsForAuthenticatedConnectionAfterManualReconnect(t *testing.T) {
	events := make(chan pairEvent, 2)
	events <- pairReconnect
	calls := 0
	err := awaitPairLogin(context.Background(), events, func(context.Context) error {
		calls++
		events <- pairAuthenticated
		return nil
	}, func() bool { return true })
	if err != nil || calls != 1 {
		t.Fatal("pair login did not complete with exactly one reconnect")
	}
}

func TestPairProtocolAcceptanceAloneDoesNotCompleteLogin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := awaitPairLogin(ctx, make(chan pairEvent), nil, func() bool { return true })
	if err == nil || err.Error() != "pair_login_timeout" {
		t.Fatal("missing authenticated event accepted")
	}
}

func TestPairDoesNotReconnectRejectedOrWrongIdentity(t *testing.T) {
	for _, valid := range []bool{true, false} {
		events := make(chan pairEvent, 1)
		events <- pairRejected
		if awaitPairLogin(context.Background(), events, func(context.Context) error {
			t.Fatal("reconnected rejected identity")
			return nil
		}, func() bool { return valid }) == nil {
			t.Fatal("rejected identity accepted")
		}
	}
}

func TestPairReconnectFailureOrSecondReconnectIsTerminal(t *testing.T) {
	for _, fail := range []bool{true, false} {
		events := make(chan pairEvent, 2)
		events <- pairReconnect
		events <- pairReconnect
		calls := 0
		err := awaitPairLogin(context.Background(), events, func(context.Context) error {
			calls++
			if fail {
				return errors.New("fixture")
			}
			return nil
		}, func() bool { return true })
		if err == nil || calls != 1 {
			t.Fatal("pair login retried beyond its bound")
		}
	}
}
