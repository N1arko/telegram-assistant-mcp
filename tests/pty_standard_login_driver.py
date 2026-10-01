"""Real CLI/getpass/SDK in a PTY, fake RPCs and fake saved settings only."""
from pathlib import Path
import sys
from pty_login_driver import command_for, run_pty


CHILD = r'''
import contextlib,json,os,socket,sys,tempfile,termios
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,TESTS_PLACEHOLDER)
def no_network(*args,**kwargs):
    raise AssertionError('network forbidden in standard CLI test')
socket.socket.connect=no_network
socket.socket.connect_ex=no_network
socket.create_connection=no_network
from test_telegram_standard_login import StandardHarness,PHONE,OTP,PASSWORD
from telegram_assistant.telegram_login import _save_private_config
import telegram_assistant.telegram_standard_login as helper
from telethon import types
mode=MODE_PLACEHOLDER
h=None
def factory(*args,**kwargs):
    global h
    h=StandardHarness(*args,mode=mode,**kwargs)
    return h.client
helper._ProbeClient=factory
with tempfile.TemporaryDirectory() as root:
    root=Path(root).resolve()
    config,session=root/'config',root/'session'
    config.mkdir(mode=0o700);session.mkdir(mode=0o700)
    _save_private_config(config/'login.json',json.dumps(dict(version=1,api_id=12345,
        api_hash='a'*32,phone=PHONE)).encode())
    sys.argv=['standard-login','--config-dir',str(config),'--session-dir',str(session)]
    flags=termios.tcgetattr(0)
    with patch('telethon.password.compute_check',return_value=types.InputCheckPasswordEmpty()) as srp:
        result=helper.main()
        if mode in {'2fa','password_invalid'}:
            assert srp.call_args.args[1]==PASSWORD
        else:
            assert srp.call_count==0
    assert termios.tcgetattr(0)==flags
    if mode=='cancel':
        assert h is None
    elif mode in {'2fa','no2fa'}:
        assert result==0 and (session/'assistant.session').is_file() and (config/'telegram.json').is_file()
    else:
        assert result==1 and not (session/'assistant.session').exists() and not (config/'telegram.json').exists()
    print('STANDARD_CLI_FAKE_PASS',flush=True)
    raise SystemExit(result)
'''


def probe(mode):
    from test_auth_lifecycle_audit import PASSWORD
    command=command_for()
    command[-1]=CHILD.replace('TESTS_PLACEHOLDER',repr(str(Path(__file__).parent.resolve()))).replace('MODE_PLACEHOLDER',repr(mode))
    steps=[(b'Type SEND (or CANCEL): ',b'CANCEL' if mode=='cancel' else b'SEND')]
    if mode not in {'cancel','migration','flood','auth_restart'}:
        steps.append((b'login code (hidden): ',b'98765'))
    if mode in {'2fa','password_invalid'}:
        steps.append((b'cloud password (hidden; Enter cancels): ',PASSWORD.encode()))
    status,output=run_pty(command,steps_override=steps,timeout=20)
    expected=0 if mode in {'2fa','no2fa'} else 1
    assert status==expected and b'STANDARD_CLI_FAKE_PASS' in output,(mode,status,output)
    for value in (PASSWORD.encode(),b'98765',b'a'*32,b'+15555550100',b'fake-only',b'fake-sensitive-rpc-text'):
        assert value not in output,('sensitive fixture appeared',mode)
    if mode=='password_invalid':
        assert b'(telegram_password_invalid)' in output
        assert b'standard_probe_rpc: check_password' in output
        assert b'standard_probe_dc_changed: no' in output
    if mode=='migration':
        assert b'(telegram_rpc_rejected_send_code)' in output
        assert b'standard_probe_rpc: send_code' in output
        assert b'standard_probe_dc_changed: yes' in output
    return output


if __name__=='__main__':
    for mode in ('2fa','no2fa','password_invalid','code_invalid','migration','flood','auth_restart','cancel'):
        probe(mode)
        print(mode+' PASS actual CLI/getpass/SDK, fake transport, no sensitive output')
