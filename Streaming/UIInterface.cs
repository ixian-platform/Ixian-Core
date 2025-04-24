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

using System;

namespace IXICore.Streaming
{
    public abstract class UIInterface
    {
        public abstract bool updateMessage(FriendMessage msg);
        public abstract bool insertMessage(FriendMessage msg, int channel);
        public abstract bool deleteMessage(byte[] msgId, int channel);
        public abstract bool updateReactions(byte[] msgId);
        public abstract bool updateGroupChatNicks(Address realSenderAddress, string nick);
        public abstract bool isChatScreenDisplayed(Address contactAddress);
        public abstract bool setContactStatus(Address contactAddress, bool onlineStatus, int unreadMessageCount, string excerpt, long timestamp);
    }

    public static class UIInterfaceHandler
    {
        private static UIInterface handlerClass = null;

        public static bool shouldRefreshContacts = true;

        public static void init(UIInterface handlerClass)
        {
            UIInterfaceHandler.handlerClass = handlerClass;
        }

        private static void verifyHandler()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in UIInterfaceHandler Class");
            }
        }

        public static bool updateMessage(FriendMessage msg)
        {
            verifyHandler();
            return handlerClass.updateMessage(msg);
        }

        public static bool insertMessage(FriendMessage msg, int channel)
        {
            verifyHandler();
            return handlerClass.insertMessage(msg, channel);
        }

        public static bool deleteMessage(byte[] msgId, int channel)
        {
            verifyHandler();
            return handlerClass.deleteMessage(msgId, channel);
        }

        public static bool updateReactions(byte[] msgId, int channel)
        {
            verifyHandler();
            return handlerClass.updateReactions(msgId);
        }

        public static bool updateGroupChatNicks(Address realSenderAddress, string nick)
        {
            verifyHandler();
            return handlerClass.updateGroupChatNicks(realSenderAddress, nick);
        }

        public static bool isChatScreenDisplayed(Address contactAddress)
        {
            verifyHandler();
            return handlerClass.isChatScreenDisplayed(contactAddress);
        }

        public static bool setContactStatus(Address contactAddress, bool onlineStatus, int unreadMessageCount, string excerpt, long timestamp)
        {
            verifyHandler();
            return handlerClass.setContactStatus(contactAddress, onlineStatus, unreadMessageCount, excerpt, timestamp);
        }
    }
}
