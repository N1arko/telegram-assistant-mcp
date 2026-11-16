// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"errors"
	"os"
	"path/filepath"
	"rsc.io/qr"
)

// Explicit one-shot provisioning path; runtime/MCP never expose this option.
type qrExport struct{ path string }

func newQRExport(path string) (*qrExport, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".png" {
		return nil, errors.New("invalid_qr_path")
	}
	if e := privateDir(filepath.Dir(path)); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, errors.New("qr_path_exists")
	}
	return &qrExport{path}, nil
}
func (q *qrExport) write(value string) error {
	code, e := qr.Encode(value, qr.L)
	if e != nil {
		return errors.New("qr_render_failed")
	}
	// Keep the phone pairing code legible when displayed in the chat preview.
	code.Scale = max(16, (1024+code.Size+7)/(code.Size+8))
	file, e := os.CreateTemp(filepath.Dir(q.path), ".pair-qr-")
	if e != nil {
		return errPrivate
	}
	temp := file.Name()
	defer os.Remove(temp)
	if e = file.Chmod(0600); e == nil {
		_, e = file.Write(code.PNG())
	}
	if e == nil {
		e = file.Sync()
	}
	file.Close()
	if e != nil {
		return errors.New("qr_write_failed")
	}
	if _, st := os.Lstat(q.path); st == nil {
		if _, e = privateRead(q.path, 1024*1024); e != nil {
			return e
		}
	} else if !os.IsNotExist(st) {
		return errPrivate
	}
	if e = os.Rename(temp, q.path); e != nil {
		return errors.New("qr_write_failed")
	}
	return nil
}
func (q *qrExport) close() { _ = os.Remove(q.path) }
