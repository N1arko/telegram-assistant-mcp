// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

type Config struct {
	AccountID          string   `json:"account_id"`
	ListenPort         int      `json:"listen_port"`
	ExpectedAccountJID string   `json:"expected_account_jid"`
	StateDir           string   `json:"state_dir"`
	TokenFile          string   `json:"token_file"`
	KeyFile            string   `json:"key_file"`
	ReadChats          []string `json:"read_chats"`
	WriteChats         []string `json:"write_chats"`
	WriteEnabled       bool     `json:"write_enabled"`
	ReadAccess         string   `json:"read_access"`
	WriteAccess        string   `json:"write_access"`
	PerMinute          int      `json:"per_minute"`
	PerDay             int      `json:"per_day"`
	// Operator attestation: session SQLite must reside on FileVault/APFS/LUKS storage.
	EncryptedVolumeConfirmed bool `json:"encrypted_volume_confirmed"`
}

var jidPattern = regexp.MustCompile(`^[0-9][0-9-]{0,79}@(s\.whatsapp\.net|g\.us|lid)$`)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var errPrivate = errors.New("unsafe_private_storage")
var accountPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var accountJIDPattern = regexp.MustCompile(`^[0-9]{5,20}@s\.whatsapp\.net$`)

func (c Config) account() string {
	if c.AccountID == "" {
		return "default"
	}
	return c.AccountID
}
func (c Config) port() int {
	if c.ListenPort == 0 {
		return 8878
	}
	return c.ListenPort
}
func (c Config) address() string { return "127.0.0.1:" + strconv.Itoa(c.port()) }
func (c Config) readMode() string {
	if c.ReadAccess == "" {
		return "allowlist"
	}
	return c.ReadAccess
}
func (c Config) writeMode() string {
	if c.WriteAccess == "" {
		return "allowlist"
	}
	return c.WriteAccess
}
func (c Config) canRead(chat string) bool {
	return jidPattern.MatchString(chat) && (c.readMode() == "all_chats" || contains(c.ReadChats, chat))
}
func (c Config) canWrite(chat string) bool {
	return c.WriteEnabled && c.canRead(chat) && (c.writeMode() == "all_chats" || contains(c.WriteChats, chat))
}

func verifyAccountState(c Config) error {
	b, e := privateRead(filepath.Join(c.StateDir, "account.id"), 32)
	if e != nil {
		if _, st := os.Lstat(filepath.Join(c.StateDir, "account.id")); os.IsNotExist(st) && c.account() == "default" {
			return nil
		}
		return errors.New("account_binding_required")
	}
	if string(b) != c.account() {
		return errors.New("account_state_mismatch")
	}
	return nil
}

func initializeState(dir, account string) error {
	if !accountPattern.MatchString(account) {
		return errors.New("invalid_account_id")
	}
	if e := privateDir(dir); e != nil {
		return e
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return errors.New("state_not_empty")
	}
	f, e := os.OpenFile(filepath.Join(dir, "account.id"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errPrivate
	}
	_, e = f.WriteString(account)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return errPrivate
	}
	if e = createSecret(filepath.Join(dir, "bridge.token")); e != nil {
		return errors.New("secret_exists_or_unwritable")
	}
	if e = createSecret(filepath.Join(dir, "history.key")); e != nil {
		return errors.New("secret_exists_or_unwritable")
	}
	return nil
}

func privateRead(path string, max int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errPrivate
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, errPrivate
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || st.Size() > max {
		return nil, errPrivate
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errPrivate
	}
	return b, nil
}

func privateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errPrivate
	}
	// Reject every symlink component, including an ancestor of the state directory.
	for p := path; p != "/"; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return errPrivate
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errPrivate
		}
		if _, e := os.Stat(filepath.Join(p, ".git")); e == nil {
			return errors.New("state_inside_repository")
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return errPrivate
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm()&0077 != 0 || s.Uid != uint32(os.Geteuid()) {
		return errPrivate
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	b, err := privateRead(path, 65536)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid_config")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return c, errors.New("invalid_config")
	}
	if !accountPattern.MatchString(c.account()) || c.port() < 1024 || c.port() > 65535 {
		return c, errors.New("invalid_account_or_port")
	}
	if (c.account() != "default" || c.ExpectedAccountJID != "") && !accountJIDPattern.MatchString(c.ExpectedAccountJID) {
		return c, errors.New("expected_account_required")
	}
	if !c.EncryptedVolumeConfirmed || c.PerMinute < 1 || c.PerMinute > 20 || c.PerDay < 1 || c.PerDay > 500 || len(c.ReadChats) > 1000 || len(c.WriteChats) > 1000 {
		return c, errors.New("invalid_config")
	}
	if (c.readMode() != "allowlist" && c.readMode() != "all_chats") || (c.writeMode() != "allowlist" && c.writeMode() != "all_chats") || (c.writeMode() == "all_chats" && c.readMode() != "all_chats") {
		return c, errors.New("invalid_access_mode")
	}
	for _, j := range append(append([]string{}, c.ReadChats...), c.WriteChats...) {
		if !jidPattern.MatchString(j) {
			return c, errors.New("invalid_chat")
		}
	}
	for _, j := range c.WriteChats {
		if !c.canRead(j) {
			return c, errors.New("write_requires_read")
		}
	}
	if err = privateDir(c.StateDir); err != nil {
		return c, err
	}
	if c.KeyFile != filepath.Join(c.StateDir, "history.key") || c.TokenFile != filepath.Join(c.StateDir, "bridge.token") {
		return c, errors.New("invalid_private_paths")
	}
	return c, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func createSecret(path string) error {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(hex.EncodeToString(data)); err != nil {
		return err
	}
	return f.Sync()
}
