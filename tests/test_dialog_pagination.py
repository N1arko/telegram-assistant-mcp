"""Pinned Telethon iterator + fake RPC: measure backend work, never network."""
import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from telethon import TelegramClient, functions, types
from telethon.sessions import MemorySession
from telegram_assistant.backend import TelethonBackend
from telegram_assistant.security import Denied, Quotas, RateGate
from telegram_assistant.service import Service, SCOPES


def response(ids, *, archived=False, broadcast=False, creator=False, username=None, terminal=False, count=10000):
    entities = [types.Channel(id=i, access_hash=i*10, title='channel', photo=None,
                              date=None, broadcast=True, creator=creator, username=username) if broadcast else
                types.User(id=i, access_hash=i*10, first_name=f'person {i}') for i in ids]
    peers = [types.PeerChannel(i) if broadcast else types.PeerUser(i) for i in ids]
    dialogs = [types.Dialog(peer=p, top_message=i, read_inbox_max_id=0, read_outbox_max_id=0,
                           unread_count=1, unread_mentions_count=0, unread_reactions_count=0,
                           unread_poll_votes_count=0, notify_settings=types.PeerNotifySettings(),
                           folder_id=1 if archived else None,
                           draft=types.DraftMessage(message='mock private draft', date=datetime.now(timezone.utc)))
               for i,p in zip(ids,peers)]
    messages = [types.Message(id=i,peer_id=p,date=datetime(2026,1,1,tzinfo=timezone.utc),
                              message='mock private last message') for i,p in zip(ids,peers)]
    kwargs = dict(dialogs=dialogs,messages=messages,
                  chats=entities if broadcast else [],users=[] if broadcast else entities)
    return types.messages.Dialogs(**kwargs) if terminal else types.messages.DialogsSlice(count=count,**kwargs)


class OfflineClient(TelegramClient):
    def __init__(self, pages):
        super().__init__(MemorySession(),12345,'a'*32,receive_updates=False,request_retries=0)
        self.pages, self.requests = list(pages), []
    async def __call__(self, request, *args, **kwargs):
        self.requests.append(copy.deepcopy(request))
        if not isinstance(request,functions.messages.GetDialogsRequest):
            raise AssertionError('unexpected RPC in fake catalogue')
        result = self.pages.pop(0)
        if isinstance(result,Exception):
            raise result
        return result
    async def connect(self):
        raise AssertionError('network forbidden')


class PaginationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = SCOPES.set(frozenset({'telegram:read'}))
    def tearDown(self):
        SCOPES.reset(self.context)
    def service(self, pages):
        self.client = OfflineClient(pages)
        self.backend = TelethonBackend(self.client)
        return Service(self.backend,gate=RateGate(limit=1000))
    async def test_limit_one_bounds_actual_catalogue_rpc_for_large_account(self):
        service = self.service([response([42],count=10000),response([43],terminal=True)])
        first = await service.invoke('list_dialogs',limit=1)
        self.assertEqual([d['peer_id'] for d in first['dialogs']],[42])
        self.assertEqual(len(self.client.requests),1)
        self.assertEqual(self.client.requests[0].limit,1)
        self.assertFalse(first['listing_complete'])
        replay = await service.invoke('list_dialogs',limit=50)
        self.assertEqual(replay['dialogs'],first['dialogs'])
        self.assertEqual(len(self.client.requests),1)
        second = await service.invoke('list_dialogs',limit=1,cursor=first['next_cursor'])
        request = self.client.requests[1]
        self.assertEqual((request.limit,request.offset_id,request.offset_peer.user_id,request.exclude_pinned),(1,42,42,True))
        self.assertEqual(second['dialogs'][0]['peer_id'],43)
        self.assertTrue(second['listing_complete'])
        cached = await service.invoke('list_dialogs',limit=1,cursor=first['next_cursor'])
        self.assertEqual(cached,second)
        self.assertEqual(len(self.client.requests),2)
    async def test_empty_filtered_page_keeps_cursor_without_hidden_fill_scan(self):
        service = self.service([response([100],broadcast=True),response([42],terminal=True)])
        first = await service.invoke('list_dialogs',limit=1)
        self.assertEqual(first['dialogs'],[])
        self.assertIsNotNone(first['next_cursor'])
        self.assertFalse(first['listing_complete'])
        self.assertEqual(len(self.client.requests),1)
        second = await service.invoke('list_dialogs',limit=1,cursor=first['next_cursor'])
        self.assertEqual(second['dialogs'][0]['peer_id'],42)
        self.assertEqual(len(self.client.requests),2)

    async def test_only_configured_owner_broadcast_is_listed_in_one_bounded_rpc(self):
        from telethon.utils import get_peer_id
        page = response([100, 200], broadcast=True, creator=True, username='owner_channel')
        page.chats[1].username = 'other_channel'
        page.chats[1].creator = False
        client = OfflineClient([page])
        allowed_peer_id = get_peer_id(page.chats[0])
        configured = (allowed_peer_id, 'owner_channel')
        backend = TelethonBackend(client, read_only_broadcast_channel=configured)
        service = Service(backend, gate=RateGate(limit=1000), read_only_broadcast_channel=configured)
        result = await service.invoke('list_dialogs', limit=2)
        self.assertEqual([row['peer_id'] for row in result['dialogs']], [allowed_peer_id])
        self.assertEqual(result['dialogs'][0]['type'], 'channel')
        self.assertEqual(len(client.requests), 1)
        self.assertEqual(client.requests[0].limit, 2)
    async def test_replay_changed_limit_never_skips_cached_tail(self):
        service = self.service([response([1,2,3],terminal=True)])
        first = await service.invoke('list_dialogs',limit=3)
        shorter = await service.invoke('list_dialogs',limit=1)
        self.assertEqual(shorter['dialogs'],first['dialogs'][:1])
        remainder = await service.invoke('list_dialogs',limit=50,cursor=shorter['next_cursor'])
        self.assertEqual(remainder['dialogs'],first['dialogs'][1:])
        self.assertTrue(remainder['listing_complete'])
        self.assertEqual(len(self.client.requests),1)
    async def test_search_known_peer_uses_history_without_catalogue_scan(self):
        service = self.service([response([42])])
        await service.invoke('list_dialogs',limit=1)
        self.client.get_messages = AsyncMock(return_value=[])
        self.client.get_input_entity = AsyncMock(return_value=types.InputPeerUser(42,420))
        self.assertEqual((await service.invoke('search_messages',peer_id=42,query='fake',limit=1))['messages'],[])
        self.client.get_messages.assert_awaited_once_with(self.backend.peers[42],limit=2,offset_id=0,search='fake')
        self.assertEqual(len(self.client.requests),1)

    async def test_incremental_catalogue_metadata_is_private_to_monitor_path(self):
        page=response([42,43],terminal=True,count=2)
        page.dialogs[0].read_inbox_max_id=7
        service=self.service([page])
        internal=await service.list_dialogs(limit=1,_monitor_metadata=True,_fresh=True)
        row=internal["dialogs"][0]
        self.assertEqual(row["latest_message_id"],42)
        self.assertEqual(row["read_inbox_max_id"],7)
        public=await service.list_dialogs(limit=1,cursor=internal["next_cursor"])
        self.assertEqual(set(public["dialogs"][0]),
                         {"peer_id","title","title_truncated","type","archived","unread"})

    async def test_monitor_catalogue_offset_resumes_after_service_restart(self):
        """Restart loses only the fast cache; its persisted TL offset resumes at the next page."""
        first_page = response(range(1, 51), count=100)
        client1 = OfflineClient([first_page])
        backend1 = TelethonBackend(client1)
        backend1.resolve = AsyncMock(side_effect=lambda target, **kw: (target, "user"))
        backend1.new_messages = AsyncMock(return_value=[])
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "quotas.sqlite"
            quotas1 = Quotas(db_path)
            service1 = Service(backend1, quotas=quotas1, gate=RateGate(limit=1000))
            first = await service1.invoke("scan_updates", limit=1)
            state = quotas1.load_monitor_state()
            self.assertEqual(state["catalog_checkpoint"]["offset_id"], 50)
            self.assertEqual(state["catalog_checkpoint"]["peer_kind"], "user")
            # Model a process death after an expired cursor was cleared but
            # before the resumed offset's first page was saved.
            state["catalog_cursor"] = None
            quotas1.save_monitor_state(state)
            quotas1.close()

            # The public cursor token refers to the prior process' volatile map.
            # A new service instance must restore the saved Peer/InputPeer offset.
            client2 = OfflineClient([response([51], terminal=True, count=100)])
            backend2 = TelethonBackend(client2)
            backend2.resolve = AsyncMock(side_effect=lambda target, **kw: (target, "user"))
            backend2.new_messages = AsyncMock(return_value=[])
            quotas2 = Quotas(db_path)
            service2 = Service(backend2, quotas=quotas2, gate=RateGate(limit=1000))
            try:
                replay = await service2.invoke("scan_updates", limit=1)
                self.assertEqual(replay["messages"], [])
                cursor = first["next_cursor"]
                # Drain enough queued first-page peers to trigger the scheduled catalog read.
                for _ in range(3):
                    result = await service2.invoke("scan_updates", limit=1, cursor=cursor)
                    cursor = result["next_cursor"]
                request = client2.requests[0]
                self.assertEqual((request.offset_id, request.offset_peer.user_id, request.exclude_pinned),
                                 (50, 50, True))
                self.assertFalse(result["coverage_restarted"])
                self.assertTrue(result["catalogue_complete"])
            finally:
                quotas2.close()

    async def test_scan_updates_unchanged_1000_dialog_catalogue_uses_catalogue_only(self):
        """A full unchanged pass costs 20 GetDialogs RPCs and zero history RPCs."""
        pages = []
        for start in range(1, 1001, 50):
            ids = range(start, min(start + 50, 1001))
            pages.append(response(ids, count=1000, terminal=(start == 951)))
        client = OfflineClient(pages)
        backend = TelethonBackend(client)
        backend.new_messages = AsyncMock(side_effect=AssertionError("unexpected history RPC"))
        self.backend, self.client = backend, client
        with tempfile.TemporaryDirectory() as tmp:
            quotas = Quotas(Path(tmp) / "runtime" / "quotas.sqlite")
            try:
                quotas.db.executemany(
                    "INSERT INTO monitor_checkpoints(peer,message_id,peer_type) VALUES(?,?,?)",
                    ((i, i, "user") for i in range(1, 1001)))
                quotas.db.commit()
                service = Service(backend, quotas=quotas, gate=RateGate(limit=1000))
                cursor = None
                for _ in range(20):
                    result = await service.invoke("scan_updates", limit=5, cursor=cursor)
                    self.assertEqual(result["messages"], [])
                    cursor = result["next_cursor"]
                self.assertTrue(result["catalogue_complete"])
                self.assertEqual(len(client.requests), 20)
                self.assertTrue(all(request.limit == 50 for request in client.requests))
                backend.new_messages.assert_not_awaited()
            finally:
                quotas.close()

    async def test_archive_is_telegram_folder_filter(self):
        for archived,folder in [(None,None),(True,1),(False,0)]:
            with self.subTest(archived=archived):
                service = self.service([response([42],archived=bool(archived),terminal=True)])
                result = await service.invoke('list_dialogs',archived=archived,limit=1)
                self.assertEqual(len(result['dialogs']),1)
                self.assertEqual(self.client.requests[0].folder_id,folder)
    async def test_pinned_extra_buffer_is_private_and_served_without_rpc(self):
        page = response([1,2,3])
        page.dialogs[0].pinned = True
        service = self.service([page])
        first = await service.invoke('list_dialogs',limit=1)
        state = next(iter(service.snapshots.values()))['state']
        self.assertTrue(all(d.message is None and d.draft is None and d.dialog.draft is None
                            for d in state.iterator.buffer))
        second = await service.invoke('list_dialogs',limit=1,cursor=first['next_cursor'])
        self.assertEqual(second['dialogs'][0]['peer_id'],2)
        self.assertEqual(len(self.client.requests),1)
        self.assertEqual(state.iterator.request.offset_id,3)
    async def test_dedup_nonprogress_and_scan_cap_are_explicitly_partial(self):
        service = self.service([response([42]),response([42])])
        first = await service.invoke('list_dialogs',limit=1)
        second = await service.invoke('list_dialogs',limit=1,cursor=first['next_cursor'])
        self.assertEqual(second['dialogs'],[])
        self.assertIsNone(second['next_cursor'])
        self.assertTrue(second['scan_truncated'])
        self.assertFalse(second['listing_complete'])
        service = self.service([response([42])])
        state = self.backend.start_dialogs(None)
        state.budget.scanned = 4999
        service.snapshots['test'] = {'state':state,'archived':None,'expires':service.clock()+300,'blocks':[]}
        result = await service.invoke('list_dialogs',limit=50)
        self.assertEqual(self.client.requests[0].limit,1)
        self.assertTrue(result['scan_truncated'])
        self.assertFalse(result['listing_complete'])
    async def test_oversized_response_rejected_without_second_rpc(self):
        service = self.service([response(range(1,202))])
        result = await service.invoke('list_dialogs',limit=1)
        self.assertEqual(result['error'],'dialog_batch_overflow')
        self.assertEqual(len(self.client.requests),1)
    async def test_flood_keeps_cursor_and_denies_rpcs_until_expiry(self):
        class FloodWaitError(Exception):
            seconds = 26
        now = [100]
        service = self.service([response([42]),FloodWaitError(),response([43],terminal=True)])
        service.gate = RateGate(clock=lambda:now[0])
        first = await service.invoke('list_dialogs',limit=1)
        kw = dict(limit=1,cursor=first['next_cursor'])
        self.assertEqual((await service.invoke('list_dialogs',**kw))['retry_after_seconds'],26)
        now[0] += 8
        self.assertEqual((await service.invoke('list_dialogs',**kw))['retry_after_seconds'],18)
        self.assertEqual(len(self.client.requests),2)
        now[0] += 18
        result = await service.invoke('list_dialogs',**kw)
        self.assertEqual(result['dialogs'][0]['peer_id'],43)
        self.assertEqual(len(self.client.requests),3)
        self.assertEqual(self.client.requests[1].offset_id,self.client.requests[2].offset_id)
    async def test_targeted_membership_and_self_resolve_never_list_catalogue(self):
        client = SimpleNamespace(get_input_entity=AsyncMock(return_value=types.InputPeerUser(42,123)))
        client.__call__ = AsyncMock()  # special methods are looked up on the type
        class TargetClient:
            get_input_entity = client.get_input_entity
            async def __call__(self,request):
                self.request = request
                return response([42],terminal=True)
        target_client = TargetClient()
        backend = TelethonBackend(target_client)
        self.assertEqual(await backend.resolve(42),(42,'user'))
        self.assertIsInstance(target_client.request,functions.messages.GetPeerDialogsRequest)
        backend._remember(types.User(id=43,is_self=True))
        target_client.get_input_entity.return_value = types.InputPeerSelf()
        self.assertEqual(await backend.resolve(43),(43,'user'))
        target_client.get_input_entity.return_value = types.InputPeerUser(777,123)
        with self.assertRaises(Denied):
            await backend.resolve(777)

    async def test_runtime_startup_and_unauthorized_call_never_activate_telegram(self):
        from telegram_assistant.server import serve
        from test_auth_transport import CONFIG
        with tempfile.TemporaryDirectory() as root:
            root = Path(root).resolve()
            session = root/'fake.session'
            session.write_bytes(b'fake-only');session.chmod(0o600)
            config = root/'telegram.json'
            config.write_text(json.dumps({'api_id':12345,'api_hash':'a'*32,'session_file':str(session)}))
            config.chmod(0o600)
            client = OfflineClient([response([42],terminal=True)])
            client.connect = AsyncMock()
            client.disconnect = AsyncMock()
            client.is_user_authorized = AsyncMock(return_value=True)
            client.get_me = AsyncMock(return_value=types.User(id=42,bot=False))
            captured = {}
            def build(service,*args,**kwargs): captured['service'] = service;return object()
            class Server:
                def __init__(self,*args): pass
                async def serve(inner):
                    client.connect.assert_not_awaited()
                    client.is_user_authorized.assert_not_awaited()
                    service = captured['service']
                    context = SCOPES.set(frozenset())
                    try:
                        self.assertEqual((await service.invoke('list_dialogs',limit=1))['error'],'unauthorized')
                    finally: SCOPES.reset(context)
                    client.connect.assert_not_awaited()
                    self.assertEqual(len(client.requests),0)
                    self.assertEqual((await service.invoke('list_dialogs',limit=1))['error'],'telegram_rate_limited')
                    client.connect.assert_not_awaited()
                    # Synthetic expiry for the one mock owner call, no sleep.
                    service.gate.blocked_until = 0
                    result = await service.invoke('list_dialogs',limit=1)
                    self.assertEqual(result['dialogs'][0]['peer_id'],42)
                    client.connect.assert_awaited_once()
                    client.is_user_authorized.assert_awaited_once()
                    client.get_me.assert_awaited_once()
                    await service.invoke('list_dialogs',limit=1)
                    self.assertEqual(client.connect.await_count,1)
                    self.assertEqual(len(client.requests),1)
            args = SimpleNamespace(auth_config=root/'auth.json',telegram_config=config,
                                   runtime_dir=root/'state',policy=root/'no-policy',read_only=True,
                                   container_network=True)
            verifier = SimpleNamespace(close=AsyncMock(), start_background_refresh=Mock())
            with patch('telegram_assistant.server.AuthConfig.load',return_value=CONFIG), \
                 patch('telethon.TelegramClient',return_value=client), \
                 patch('telegram_assistant.server.JWKSVerifier',return_value=verifier), \
                 patch('telegram_assistant.server.build_mcp',side_effect=build), \
                 patch('telegram_assistant.server.build_app',return_value=object()), \
                 patch('uvicorn.Server',Server):
                await serve(args)
            verifier.start_background_refresh.assert_called_once_with()
            verifier.close.assert_awaited_once()
            client.disconnect.assert_awaited_once()


class PersistentRateTests(unittest.TestCase):
    def test_restart_preserves_local_rate_window_without_flood(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'quotas.sqlite'
            quotas = Quotas(path)
            RateGate(limit=1,clock=lambda:100,wall_clock=lambda:1000,storage=quotas).check()
            quotas.close()
            quotas = Quotas(path)
            gate = RateGate(limit=1,clock=lambda:10,wall_clock=lambda:1008,storage=quotas)
            with self.assertRaises(Denied) as raised:gate.check()
            self.assertEqual((raised.exception.code,raised.exception.retry_after),('local_rate_limited',52))
            quotas.close()
    def test_restart_preserves_flood_and_rolling_calls(self):
        with tempfile.TemporaryDirectory() as root:
            now,wall = [100],[1000]
            path = Path(root)/'quotas.sqlite'
            quotas = Quotas(path)
            gate = RateGate(limit=2,clock=lambda:now[0],wall_clock=lambda:wall[0],storage=quotas)
            gate.check();gate.check();gate.flood(123)
            quotas.close()
            now[0],wall[0] = 10,1008
            quotas = Quotas(path)
            gate = RateGate(limit=2,clock=lambda:now[0],wall_clock=lambda:wall[0],storage=quotas,startup_grace=60)
            with self.assertRaises(Denied) as raised: gate.check()
            self.assertEqual(raised.exception.retry_after,115)
            state = quotas.load_gate()
            self.assertEqual(set(state),{'version','flood_until','calls'})
            now[0],wall[0] = 125,1123
            gate.check()
            quotas.close()
    def test_grace_and_storage_failure_fail_closed(self):
        store = SimpleNamespace(load_gate=lambda:None,save_gate=lambda value:None)
        now = [0]
        gate = RateGate(storage=store,clock=lambda:now[0],wall_clock=lambda:1000+now[0],startup_grace=60)
        with self.assertRaises(Denied) as raised: gate.check()
        self.assertEqual(raised.exception.retry_after,60)
        now[0] = 60
        def fail(value): raise RuntimeError('mock disk failure')
        store.save_gate = fail
        with self.assertRaises(Denied) as raised: gate.check()
        self.assertEqual(raised.exception.code,'rate_state_unavailable')
        with self.assertRaises(Denied): gate.check()
        for state in [ {'version':True,'flood_until':0,'calls':[]},
                       {'version':1,'flood_until':float('nan'),'calls':[]},
                       {'version':1,'flood_until':0,'calls':[2,1]} ]:
            store.load_gate = lambda:state
            with self.assertRaises(Denied): RateGate(storage=store)
