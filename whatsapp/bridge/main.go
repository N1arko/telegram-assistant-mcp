// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

// Personal WhatsApp bridge. QR is available only on a separately opened private TTY.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	signalLogger "go.mau.fi/libsignal/logger"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"rsc.io/qr"
)

func writeRevoked(dir string) error {
	return os.WriteFile(filepath.Join(dir, "revoked"), []byte("manual_relink_required\n"), 0600)
}
func safeDB(path string) (*os.File, error) {
	fd, e := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, errPrivate
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, errPrivate
	}
	s := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 {
		f.Close()
		return nil, errPrivate
	}
	return f, nil
}
func backoff(attempt int) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	return time.Second * time.Duration(1<<attempt)
}

type reconnectTarget interface {
	SessionValid() bool
	ConnectionOpen() bool
	Connect(context.Context) error
}

func (w *WhatsApp) SessionValid() bool {
	return !w.revoked.Load() && !w.storageFailed.Load() && w.client != nil && w.client.Store.ID != nil
}
func (w *WhatsApp) ConnectionOpen() bool              { return w.client.IsConnected() }
func (w *WhatsApp) Connect(ctx context.Context) error { return w.client.ConnectContext(ctx) }
func reconnect(ctx context.Context, w reconnectTarget) {
	reconnectLoop(ctx, w, func(ctx context.Context, d time.Duration) bool {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	})
}
func reconnectLoop(ctx context.Context, w reconnectTarget, wait func(context.Context, time.Duration) bool) {
	attempt := 0
	for ctx.Err() == nil && w.SessionValid() {
		if !w.ConnectionOpen() {
			if e := w.Connect(ctx); e != nil {
				attempt++
			} else {
				attempt = 0
			}
		}
		if !wait(ctx, backoff(attempt)) {
			return
		}
	}
}

type signalNoop struct{}

func (signalNoop) Debug(string, string)   {}
func (signalNoop) Info(string, string)    {}
func (signalNoop) Warning(string, string) {}
func (signalNoop) Error(string, string)   {}
func (signalNoop) Configure(string)       {}
func silenceLibraries()                   { log.SetOutput(io.Discard); signalLogger.Logger = signalNoop{} }

func run() error {
	syscall.Umask(0077)
	silenceLibraries()
	if len(os.Args) < 2 {
		return errors.New("usage_init_pair_run_chats")
	}
	mode := os.Args[1]
	f := flag.NewFlagSet("wa-bridge", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "owner-only WhatsApp config")
	dir := f.String("state-dir", "", "private state for init")
	account := f.String("account-id", "default", "public account label for init")
	qrFile := f.String("qr-file", "", "pair only: ephemeral owner-only QR PNG, never stdout")
	if e := f.Parse(os.Args[2:]); e != nil || f.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if *qrFile != "" && mode != "pair" {
		return errors.New("qr_export_pair_only")
	}
	if mode == "init" {
		if *config != "" {
			return errors.New("invalid_arguments")
		}
		if !filepath.IsAbs(*dir) {
			return errPrivate
		}
		if e := os.MkdirAll(*dir, 0700); e != nil {
			return errPrivate
		}
		if e := privateDir(*dir); e != nil {
			return e
		}
		for p := *dir; p != "/"; p = filepath.Dir(p) {
			if _, e := os.Stat(filepath.Join(p, ".git")); e == nil {
				return errors.New("state_inside_repository")
			}
		}
		return initializeState(*dir, *account)
	}
	if mode != "pair" && mode != "run" && mode != "chats" {
		return errors.New("invalid_mode")
	}
	c, e := loadConfig(*config)
	if e != nil {
		return e
	}
	accountFlag := false
	f.Visit(func(v *flag.Flag) {
		if v.Name == "account-id" {
			accountFlag = true
		}
	})
	if *dir != "" || (accountFlag && *account != c.account()) {
		return errors.New("account_config_mismatch")
	}
	if e = verifyAccountState(c); e != nil {
		return e
	}
	lock, e := safeDB(filepath.Join(c.StateDir, "bridge.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("session_in_use")
	}
	if _, e = os.Lstat(filepath.Join(c.StateDir, "revoked")); e == nil {
		return errors.New("session_revoked_manual_relink_required")
	} else if !os.IsNotExist(e) {
		return errPrivate
	}
	for _, name := range []string{"session.db", "history.sqlite"} {
		f, e := safeDB(filepath.Join(c.StateDir, name))
		if e != nil {
			return e
		}
		f.Close()
	}
	kb, e := privateRead(c.KeyFile, 64)
	if e != nil {
		return e
	}
	key, e := hex.DecodeString(string(kb))
	if e != nil || len(key) != 32 {
		return errors.New("invalid_key")
	}
	tb, e := privateRead(c.TokenFile, 64)
	if e != nil {
		return e
	}
	token := string(tb)
	decoded, e := hex.DecodeString(token)
	if e != nil || len(decoded) != 32 {
		return errors.New("invalid_token")
	}
	store, e := openStore(filepath.Join(c.StateDir, "history.sqlite"), key)
	if e != nil {
		return errors.New("storage_unavailable")
	}
	defer store.db.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	devices, e := sqlstore.New(ctx, "sqlite3", "file:"+filepath.Join(c.StateDir, "session.db")+"?_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL", waLog.Noop)
	if e != nil {
		return errors.New("session_storage_unavailable")
	}
	defer devices.Close()
	device, e := devices.GetFirstDevice(ctx)
	if e != nil {
		return errors.New("session_unavailable")
	}
	if device.ID != nil && c.ExpectedAccountJID != "" && device.ID.ToNonAD().String() != c.ExpectedAccountJID {
		return errors.New("session_account_mismatch")
	}
	client := whatsmeow.NewClient(device, waLog.Noop)
	mediaTransport := http.DefaultTransport.(*http.Transport).Clone()
	mediaTransport.Proxy = nil
	client.SetMediaHTTPClient(&http.Client{Transport: cappedTransport{base: mediaTransport}, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	defer client.Disconnect()
	client.EnableAutoReconnect = false
	client.InitialAutoReconnect = false
	client.DisableLoginAutoReconnect = true
	client.AutomaticMessageRerequestFromPhone = false
	client.UseRetryMessageStore = false
	client.PreRetryCallback = func(*events.Receipt, string, int, *waE2E.Message) bool { return false }
	w := &WhatsApp{client: client, store: store, cfg: c}
	client.AddEventHandler(w.event)
	if mode == "pair" {
		if device.ID != nil {
			return errors.New("session_already_linked")
		}
		pairing := make(chan pairEvent, 8)
		client.AddEventHandler(func(event any) {
			var value pairEvent
			switch event.(type) {
			case *events.Connected:
				value = pairAuthenticated
			case *events.ManualLoginReconnect:
				value = pairReconnect
			case events.PermanentDisconnect:
				value = pairRejected
			default:
				return
			}
			select {
			case pairing <- value:
			default:
			}
		})
		var export *qrExport
		if *qrFile != "" {
			export, e = newQRExport(*qrFile)
			if e != nil {
				return e
			}
			defer export.close()
		}
		tty, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if e != nil {
			return errors.New("private_tty_required")
		}
		defer tty.Close()
		fmt.Fprintln(tty, "Link a persistent personal WhatsApp companion. Type PAIR to continue:")
		answer, e := bufio.NewReader(tty).ReadString('\n')
		if e != nil || strings.TrimSpace(answer) != "PAIR" {
			return errors.New("pair_cancelled")
		}
		qrCtx, stop := context.WithTimeout(ctx, 180*time.Second)
		defer stop()
		codes, e := client.GetQRChannel(qrCtx)
		if e != nil {
			return errors.New("pair_unavailable")
		}
		if export == nil {
			fmt.Fprint(tty, "\x1b[?1049h")
			defer fmt.Fprint(tty, "\x1b[2J\x1b[H\x1b[?1049l")
		}
		if client.ConnectContext(qrCtx) != nil {
			return errors.New("pair_connection_failed")
		}
		for code := range codes {
			switch code.Event {
			case "code":
				if export != nil {
					if export.write(code.Code) != nil {
						return errors.New("qr_write_failed")
					}
				} else {
					fmt.Fprint(tty, "\x1b[2J\x1b[H")
					if renderQR(tty, code.Code) != nil {
						return errors.New("qr_render_failed")
					}
				}
			case "success":
				if device.ID == nil || w.revoked.Load() || (c.ExpectedAccountJID != "" && device.ID.ToNonAD().String() != c.ExpectedAccountJID) {
					_ = writeRevoked(c.StateDir)
					return errors.New("paired_account_mismatch")
				}
				return awaitPairLogin(qrCtx, pairing, func(ctx context.Context) error {
					client.Disconnect()
					return client.ConnectContext(ctx)
				}, func() bool {
					return w.SessionValid() && (c.ExpectedAccountJID == "" || device.ID.ToNonAD().String() == c.ExpectedAccountJID)
				})
			case "timeout":
				return errors.New("pair_timeout")
			}
		}
		return errors.New("pair_incomplete")
	}
	if device.ID == nil {
		return errors.New("session_not_linked")
	}
	if mode == "chats" {
		tty, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if e != nil {
			return errors.New("private_tty_required")
		}
		defer tty.Close()
		ready := make(chan struct{}, 1)
		client.AddEventHandler(func(v any) {
			if _, ok := v.(*events.Connected); ok {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		})
		short, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		if client.ConnectContext(short) != nil {
			return errors.New("connection_failed")
		}
		select {
		case <-ready:
		case <-short.Done():
			return errors.New("connection_timeout")
		}
		contacts, e := device.Contacts.GetAllContacts(short)
		if e != nil {
			return errors.New("contacts_unavailable")
		}
		for jid, c := range contacts {
			fmt.Fprintf(tty, "%s  %s\n", jid.String(), sanitizeName(c.FullName))
			if device.LIDs != nil {
				if lid, err := device.LIDs.GetLIDForPN(short, jid); err == nil && !lid.IsEmpty() {
					fmt.Fprintf(tty, "%s  %s (LID alias; allow explicitly if needed)\n", lid.String(), sanitizeName(c.FullName))
				}
			}
		}
		groups, e := client.GetJoinedGroups(short)
		if e != nil {
			return errors.New("groups_unavailable")
		}
		for _, g := range groups {
			fmt.Fprintf(tty, "%s  %s\n", g.JID.String(), sanitizeName(g.Name))
		}
		return nil
	}
	go reconnect(ctx, w)
	b := &Bridge{cfg: c, store: store, wa: w, token: token, clock: time.Now}
	server := &http.Server{Addr: c.address(), Handler: http.HandlerFunc(b.handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("bridge_listener_failed")
		}
	case <-ctx.Done():
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return nil
}

func renderQR(w io.Writer, value string) error {
	code, e := qr.Encode(value, qr.L)
	if e != nil {
		return e
	}
	// Explicit black on white, four-module quiet zone, two modules per row.
	// This renderer receives the private TTY directly and never emits the token.
	if _, e = io.WriteString(w, "\x1b[30;47m"); e != nil {
		return e
	}
	for y := -4; y < code.Size+4; y += 2 {
		var line strings.Builder
		for x := -4; x < code.Size+4; x++ {
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			switch {
			case top && bottom:
				line.WriteRune('█')
			case top:
				line.WriteRune('▀')
			case bottom:
				line.WriteRune('▄')
			default:
				line.WriteByte(' ')
			}
		}
		line.WriteString("\x1b[0m\n\x1b[30;47m")
		if _, e = io.WriteString(w, line.String()); e != nil {
			return e
		}
	}
	_, e = io.WriteString(w, "\x1b[0m")
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "whatsapp_bridge_failed")
		os.Exit(1)
	}
}
