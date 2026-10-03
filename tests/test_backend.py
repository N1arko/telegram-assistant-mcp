import unittest
import time
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock
from pathlib import Path

from telethon.tl.types import User, Chat, Channel, InputPeerUser, PeerUser, Message, MessageReplyHeader
from telegram_assistant.backend import TelethonBackend
from telegram_assistant.security import Denied
from telegram_assistant.media import OutboundMediaFile


class BackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = NS(get_dialogs=AsyncMock(),get_messages=AsyncMock(),get_input_entity=AsyncMock(),
                         send_message=AsyncMock(),send_file=AsyncMock(),send_read_acknowledge=AsyncMock(),download_media=AsyncMock())
        self.backend=TelethonBackend(self.client)
    async def test_archive_and_marked_ids_and_membership(self):
        user=User(id=42,first_name="Test")
        chat=Chat(id=99,title="Group",photo=None,participants_count=2,date=None,version=1)
        group=Channel(id=123,title="Supergroup",photo=None,date=None,megagroup=True)
        broadcast=Channel(id=124,title="Broadcast",photo=None,date=None,broadcast=True)
        self.assertEqual([self.backend._remember(e) for e in [user,chat,group]],[42,-99,-1000000000123])
        self.assertEqual(self.backend.kind(broadcast),'broadcast_channel')
        self.client.get_input_entity.return_value=InputPeerUser(42,123)
        self.assertEqual(await self.backend.resolve(42),(42,"user"))
        self.client.get_input_entity.side_effect=ValueError('not in cache')
        with self.assertRaises(Denied):await self.backend.resolve(777)
        self.client.get_dialogs.assert_not_awaited()
    async def test_telethon_read_args_and_no_ack(self):
        self.backend.peers={42:User(id=42)}
        message=Message(id=10,peer_id=PeerUser(42),date=datetime.now(timezone.utc),message="caption",
                        reply_to=MessageReplyHeader(reply_to_msg_id=3))
        self.client.get_messages.return_value=[message]
        data=await self.backend.history(42,limit=4,before_id=11,query="caption")
        self.client.get_messages.assert_awaited_with(self.backend.peers[42],limit=4,offset_id=11,search="caption")
        self.assertEqual(data[0]["reply_to"],3)
        self.client.get_messages.return_value=message
        await self.backend.message(42,10)
        self.client.get_messages.assert_awaited_with(self.backend.peers[42],ids=10)
        self.client.get_messages.return_value=[message]
        await self.backend.around(42,10,3)
        self.client.get_messages.assert_any_await(self.backend.peers[42],limit=3,max_id=10)
        self.client.get_messages.assert_any_await(self.backend.peers[42],limit=3,min_id=10,reverse=True)
        self.client.send_read_acknowledge.assert_not_awaited()
        self.client.download_media.assert_not_awaited()
        self.client.send_message.assert_not_awaited()
    async def test_send_plain_text_adapter_only_mock(self):
        self.backend.peers={42:User(id=42)}
        self.client.send_message.return_value=NS(id=100)
        self.assertEqual(await self.backend.send(42,"**test**",3),100)
        self.client.send_message.assert_awaited_once_with(self.backend.peers[42],"**test**",parse_mode=None,
                                                        link_preview=False,reply_to=3)

    async def test_media_album_uses_only_photo_video_local_files(self):
        self.backend.peers={42:User(id=42)}
        self.client.send_file.return_value=[NS(id=101), NS(id=102)]
        files=[OutboundMediaFile(Path("/private/a.jpg"),"photo","image/jpeg","a.jpg",None),
               OutboundMediaFile(Path("/private/b.mp4"),"video","video/mp4","b.mp4","clip",
                                 duration=4,width=320,height=240,has_audio=True)]
        self.assertEqual(await self.backend.send_media_files(42,files,7),[101,102])
        self.client.send_file.assert_awaited_once_with(self.backend.peers[42],
            [Path("/private/a.jpg"),Path("/private/b.mp4")],caption=["","clip"],reply_to=7,
            parse_mode=None,supports_streaming=True)

    async def test_voice_and_sticker_have_required_telegram_attributes(self):
        from telethon import types
        self.backend.peers={42:User(id=42)}
        self.client.send_file.return_value=NS(id=103)
        voice=OutboundMediaFile(Path("/private/voice.ogg"),"voice","audio/ogg","voice.ogg",None,
                                duration=3,voice=True)
        self.assertEqual(await self.backend.send_media_files(42,[voice],None),[103])
        voice_kwargs=self.client.send_file.await_args.kwargs
        audio=next(a for a in voice_kwargs["attributes"] if isinstance(a,types.DocumentAttributeAudio))
        self.assertTrue(audio.voice)
        self.assertTrue(voice_kwargs["voice_note"])

        self.client.send_file.reset_mock()
        self.client.send_file.return_value=NS(id=104)
        sticker=OutboundMediaFile(Path("/private/sticker.webp"),"sticker","image/webp","sticker.webp",None,
                                  sticker_emoji="🙂",width=512,height=512)
        self.assertEqual(await self.backend.send_media_files(42,[sticker],None),[104])
        sticker_kwargs=self.client.send_file.await_args.kwargs
        attribute=next(a for a in sticker_kwargs["attributes"] if isinstance(a,types.DocumentAttributeSticker))
        self.assertEqual(attribute.alt,"🙂")
        self.assertIsInstance(attribute.stickerset,types.InputStickerSetEmpty)

    async def test_first_inbound_verifies_real_message_and_oldest_available_history(self):
        user=User(id=42,first_name="Synthetic",bot=False)
        self.backend._remember(user)
        incoming=NS(id=7,out=False,sender_id=42)
        self.client.get_messages.side_effect=[incoming,[incoming]]
        self.assertTrue(await self.backend.is_human_user(42))
        self.assertTrue(await self.backend.verify_first_inbound(42,7))
        self.assertEqual(self.client.get_messages.await_args_list,
                         [((user,),{"ids":7}),((user,),{"limit":1,"reverse":True})])

    async def test_first_inbound_fails_closed_for_bots_outgoing_missing_or_older_history(self):
        bot=User(id=42,first_name="Synthetic bot",bot=True)
        self.backend._remember(bot)
        self.assertFalse(await self.backend.is_human_user(42))
        self.assertFalse(await self.backend.verify_first_inbound(42,7))
        user=User(id=43,first_name="Synthetic",bot=False)
        self.backend._remember(user)
        outgoing=NS(id=7,out=True,sender_id=43)
        self.client.get_messages.return_value=outgoing
        self.assertFalse(await self.backend.verify_first_inbound(43,7))
        incoming=NS(id=8,out=False,sender_id=43)
        self.client.get_messages.side_effect=[incoming,[NS(id=2,out=True,sender_id=43)]]
        self.assertFalse(await self.backend.verify_first_inbound(43,8))
        self.client.get_messages.side_effect=[incoming,[]]
        self.assertFalse(await self.backend.verify_first_inbound(43,8))

    async def test_incomplete_user_entity_is_not_classified_as_human(self):
        incomplete=User(id=44,first_name="Synthetic",bot=False,min=True)
        self.backend.peers[44]=incomplete
        self.assertFalse(await self.backend.is_human_user(44))
        self.assertFalse(await self.backend.verify_first_inbound(44,8))

    async def test_own_account_is_not_classified_as_human(self):
        own=User(id=45,first_name="Synthetic self",bot=False,is_self=True)
        self.backend._remember(own)
        self.assertFalse(await self.backend.is_human_user(45))
