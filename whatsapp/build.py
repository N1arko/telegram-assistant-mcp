#!/usr/bin/env python3
"""Build the pinned bridge with a fail-closed no-resend SDK patch.

No upstream scripts are executed. The module cache is never modified. A complete
MPL-2.0 send.go copy retains its copyright/license header in ignored work/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

VERSION = "v0.0.0-20260917111002-2e338d0ee73d"
SEND_SHA256 = "b96f7a758f8cd5c1d9b81c0072b8d17e07d2ee2e77ff61b0c3f38cccf9bde81f"
USER_SHA256 = "da4c68aa720fbf9b542498e72a16ce0a56ac8e45ddd05595d02e976cd193dd62"
OLD = '''	if isDisconnectNode(respNode) {
		start = time.Now()
		respNode, err = cli.retryFrame(ctx, "message send", req.ID, data, respNode, 0)
		resp.DebugTimings.Retry = time.Since(start)
		if err != nil {
			return
		}
	}'''
NEW = '''	if isDisconnectNode(respNode) {
		// Personal MCP: an uncertain send is terminal; never resend its frame.
		err = ErrNotConnected
		return
	}'''


def prepare(go, bridge, work):
    module = json.loads(subprocess.check_output(
        [go, "mod", "download", "-json", "go.mau.fi/whatsmeow@" + VERSION], cwd=bridge))
    source = Path(module["Dir"]) / "send.go"
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SEND_SHA256:
        raise SystemExit("Unexpected pinned SDK source; review before building")
    if hashlib.sha256((source.parent / "user.go").read_bytes()).hexdigest() != USER_SHA256:
        raise SystemExit("Unexpected pinned USync source; review before building")
    text = raw.decode()
    if text.count(OLD) != 1:
        raise SystemExit("SDK retry guard could not be applied")
    patched = text.replace(OLD, NEW).replace("var data []byte\n\tswitch to.Server", "var data []byte\n\t_ = data\n\tswitch to.Server")
    work.mkdir(parents=True, exist_ok=True)
    target = work / "whatsmeow"
    # A private source copy is used because Go disallows overlays in GOMODCACHE.
    # Never modify the shared module cache or the repository's dependency files.
    if target.exists():
        for p in target.rglob("*"):
            p.chmod(0o700 if p.is_dir() else 0o600)
        target.chmod(0o700)
        shutil.rmtree(target)
    shutil.copytree(source.parent, target, copy_function=shutil.copyfile)
    target.chmod(0o700)
    (target / "send.go").write_text(patched)
    shutil.copyfile(bridge.parent / "sdk/contact_lookup.go", target / "personal_mcp_contact_lookup.go")
    modfile = work / "bridge.mod"
    modfile.write_text((bridge / "go.mod").read_text() + "\nreplace go.mau.fi/whatsmeow => " + json.dumps(str(target)) + "\n")
    shutil.copyfile(bridge / "go.sum", work / "bridge.sum")
    return modfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    bridge = root / "whatsapp/bridge"
    work = root / "work/whatsapp-build"
    path = prepare(args.go, bridge, work)
    cmd = [args.go, "test", "-race", "-modfile", str(path), "./..."] if args.test else [
        args.go, "build", "-trimpath", "-modfile", str(path), "-o", str(bridge / "wa-bridge"), "."]
    subprocess.run(cmd, cwd=bridge, check=True)


if __name__ == "__main__":
    main()
