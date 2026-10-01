"""Standard getpass + real SDK start, fake RPCs; no custom TTY reader."""
from pathlib import Path
import sys
from pty_login_driver import command_for, run_pty


CHILD = r'''
import asyncio,contextlib,getpass,io,socket,sys,termios,warnings
from unittest.mock import patch
sys.path.insert(0,TESTS_PLACEHOLDER)
def no_network(*args,**kwargs):
    raise AssertionError('network forbidden in std getpass audit')
socket.socket.connect=no_network
socket.socket.connect_ex=no_network
socket.create_connection=no_network
from test_auth_lifecycle_audit import AuthHarness,PHONE,OTP
from telethon import types
expected=PASSWORD_PLACEHOLDER
flags=termios.tcgetattr(0)
def secret(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        return getpass.getpass(prompt)
async def run():
    h=AuthHarness()
    with patch('telethon.password.compute_check',return_value=types.InputCheckPasswordEmpty()) as srp:
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            await h.client.start(phone=PHONE,max_attempts=1,
                code_callback=lambda:secret('STD code (hidden): '),
                password=lambda:secret('STD password (hidden): '))
        assert srp.call_args.args[1]==expected
        assert sum(name=='CheckPasswordRequest' for name,_ in h.calls)==1
asyncio.run(run())
assert termios.tcgetattr(0)==flags
print('STOCK_GETPASS_AND_SDK_EXACT_PASS',flush=True)
'''


def probe(value):
    command=command_for()
    command[-1]=CHILD.replace('TESTS_PLACEHOLDER',repr(str(Path(__file__).parent.resolve()))).replace('PASSWORD_PLACEHOLDER',repr(value))
    code,output=run_pty(command,steps_override=[(b'STD code (hidden): ',b'98765'),
                       (b'STD password (hidden): ',value.encode())])
    assert code==0 and b'STOCK_GETPASS_AND_SDK_EXACT_PASS' in output,'stock getpass fake audit failed'
    assert value.encode() not in output and b'98765' not in output
    return output


if __name__=='__main__':
    for name,value in (('ASCII-specials','fake_$`\\!@#%&\'"()[]{}'),
                       ('edge-spaces','  fake spaced pass  '),('Unicode','фиктивный_秘密_🙂'),
                       ('NFD','fake_Cafe\u0301')):
        probe(value)
        print(name+' PASS std getpass + real SDK start, exact fake string, no echo/network')
