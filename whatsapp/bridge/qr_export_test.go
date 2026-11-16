// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nikita Arkhipov

package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateQRExportRotatesAndCleansUp(t *testing.T) {
	dir := privateTemp(t)
	path := filepath.Join(dir, "pair.png")
	q, e := newQRExport(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = q.write("synthetic-qr-one"); e != nil {
		t.Fatal(e)
	}
	first, _ := os.ReadFile(path)
	file, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	image, e := png.DecodeConfig(file)
	file.Close()
	if e != nil || image.Width < 1024 || image.Height != image.Width {
		t.Fatal("invalid QR PNG")
	}
	if st, e := os.Stat(path); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("unsafe QR permissions")
	}
	if e = q.write("synthetic-qr-two"); e != nil {
		t.Fatal(e)
	}
	second, _ := os.ReadFile(path)
	if string(first) == string(second) {
		t.Fatal("QR did not rotate")
	}
	if _, e = newQRExport(path); e == nil {
		t.Fatal("existing file would be overwritten")
	}
	q.close()
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("QR left after provisioning")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("temporary QR residue")
	}
}
func TestQRExportRefusesPublicDirectoryAndSymlink(t *testing.T) {
	dir := privateTemp(t)
	os.Chmod(dir, 0755)
	if _, e := newQRExport(filepath.Join(dir, "pair.png")); e == nil {
		t.Fatal("public QR directory accepted")
	}
	os.Chmod(dir, 0700)
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("fixture"), 0600)
	path := filepath.Join(dir, "pair.png")
	os.Symlink(target, path)
	if _, e := newQRExport(path); e == nil {
		t.Fatal("QR symlink accepted")
	}
}
