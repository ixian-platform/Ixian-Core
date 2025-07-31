// Copyright (C) 2017-2025 Ixian
// This file is part of Ixian Core - www.github.com/ixian-platform/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.SpixiBot;
using IXICore.Streaming.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore
{
    public static class SpixiMessageObjectMap
    {
        public static readonly Dictionary<SpixiMessageCode, Func<byte[], object>> typeFactory =
            new Dictionary<SpixiMessageCode, Func<byte[], object>>
            {
                { SpixiMessageCode.chat, UTF8Encoding.UTF8.GetString },
                { SpixiMessageCode.getNick, data => data },
                { SpixiMessageCode.nick, UTF8Encoding.UTF8.GetString },
                { SpixiMessageCode.requestAdd, data => data },
                { SpixiMessageCode.acceptAdd, data => data },
                { SpixiMessageCode.sentFunds, data => data },
                { SpixiMessageCode.requestFunds, data => data },
                { SpixiMessageCode.keys, data => new KeysMessage(data) },
                { SpixiMessageCode.msgRead, data => data },
                { SpixiMessageCode.msgReceived, data => data },
                /*{ SpixiMessageCode.fileData, data => new FileDataMessage(data) },
                { SpixiMessageCode.requestFileData, data => new RequestFileDataMessage(data) },
                { SpixiMessageCode.fileHeader, data => new FileHeaderMessage(data) },
                { SpixiMessageCode.acceptFile, data => new AcceptFileMessage(data) },
                { SpixiMessageCode.requestCall, data => new RequestCallMessage(data) },
                { SpixiMessageCode.acceptCall, data => new AcceptCallMessage(data) },
                { SpixiMessageCode.rejectCall, data => new RejectCallMessage(data) },
                { SpixiMessageCode.callData, data => new CallDataMessage(data) },*/
                { SpixiMessageCode.requestFundsResponse, data => data },
                { SpixiMessageCode.acceptAddBot, data => data },
                { SpixiMessageCode.botGetMessages, data => data },
                { SpixiMessageCode.appData, data => new AppDataMessage(data) },
                /*{ SpixiMessageCode.appRequest, data => new AppRequestMessage(data) },
                { SpixiMessageCode.fileFullyReceived, data => new FileFullyReceivedMessage(data) },*/
                { SpixiMessageCode.avatar, data => data },
                { SpixiMessageCode.getAvatar, data => data },
                { SpixiMessageCode.getPubKey, data => data },
                { SpixiMessageCode.pubKey, data => data },
                /*{ SpixiMessageCode.appRequestAccept, data => new AppRequestAcceptMessage(data) },
                { SpixiMessageCode.appRequestReject, data => new AppRequestRejectMessage(data) },
                { SpixiMessageCode.appRequestError, data => new AppRequestErrorMessage(data) },
                { SpixiMessageCode.appEndSession, data => new AppEndSessionMessage(data) },*/
                { SpixiMessageCode.botAction, data => new SpixiBotAction(data) },
                { SpixiMessageCode.msgDelete, data => data },
                { SpixiMessageCode.msgReaction, data => new ReactionMessage(data) },
                { SpixiMessageCode.msgTyping, data => data },
                //{ SpixiMessageCode.msgError, data => new MsgErrorMessage(data) },
                { SpixiMessageCode.leave, data => data },
                { SpixiMessageCode.leaveConfirmed, data => data },
                { SpixiMessageCode.msgReport, data => data },
                { SpixiMessageCode.requestAdd2, data => new RequestAdd2Message(data) },
                { SpixiMessageCode.acceptAdd2, data => new AcceptAdd2Message(data) },
                { SpixiMessageCode.keys2, data => new Keys2Message(data) },
                { SpixiMessageCode.getAppProtocols, data => data },
                { SpixiMessageCode.appProtocols, data => new AppProtocolsMessage(data) },
                { SpixiMessageCode.appProtocolData, data => new AppDataMessage(data) },
            };

        public static object MapTypeToModel(SpixiMessageCode type, byte[] data)
        {
            return typeFactory.TryGetValue(type, out var constructor) ? constructor(data) : null;
        }
    }

}
