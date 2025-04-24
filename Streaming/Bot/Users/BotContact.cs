// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
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
using System.IO;
using System.Text;

namespace IXICore.SpixiBot
{
    public enum BotContactStatus
    {
        normal,
        kicked,
        banned,
        left
    }

    public class BotContact
    {
        private string nick = "";
        public byte[] nickData { get; private set; }
        public byte[] publicKey;
        private string role = "";
        public bool hasAvatar = false;
        public bool sendNotification = false;
        public BotContactStatus status = BotContactStatus.normal;

        public BotContact(byte[] nick_data, byte[] public_key, int role_index, bool has_avatar, bool send_notification = false, BotContactStatus status = BotContactStatus.normal)
        {
            setNick(nick_data);
            publicKey = public_key;
            setRole(role_index);
            hasAvatar = has_avatar;
            sendNotification = send_notification;
            this.status = status;
        }

        public string getNick()
        {
            return nick;
        }

        public void setNick(string nick)
        {
            nickData = null;
            this.nick = nick;
        }

        public void setNick(byte[] nick_data)
        {
            nickData = nick_data;
            if(nickData != null)
            {
                try
                {
                    byte[] nickBytes = new SpixiMessage(new StreamMessage(nickData).data).data;
                    if(nickBytes != null)
                    {
                        nick = Encoding.UTF8.GetString(nickBytes);
                    }
                }
                catch(Exception)
                {
                }
            }
        }

        public BotContact(byte[] contact_bytes, bool nick_as_string)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    if(nick_as_string)
                    {
                        nick = reader.ReadString();
                    }else
                    {
                        int nd_length = reader.ReadInt32();
                        if (nd_length > 0)
                        {
                            setNick(reader.ReadBytes(nd_length));
                        }
                    }

                    int pk_length = reader.ReadInt32();
                    if (pk_length > 0)
                    {
                        publicKey = reader.ReadBytes(pk_length);
                    }

                    // TODO try/catch wrapper can be removed after upgrade
                    try
                    {
                        if (m.Position < m.Length)
                        {
                            role = reader.ReadString();
                            hasAvatar = reader.ReadBoolean();
                            sendNotification = reader.ReadBoolean();
                            status = (BotContactStatus)reader.ReadInt16();
                        }
                    }catch(Exception)
                    {

                    }
                }
            }
        }

        public byte[] getBytes(bool nick_as_string)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(nick_as_string)
                    {
                        writer.Write(nick);
                    }else
                    {
                        if (nickData == null)
                        {
                            writer.Write((int)0);
                        }
                        else
                        {
                            writer.Write(nickData.Length);
                            writer.Write(nickData);
                        }
                    }

                    if (publicKey == null)
                    {
                        writer.Write((int)0);
                    }
                    else
                    {
                        writer.Write(publicKey.Length);
                        writer.Write(publicKey);
                    }

                    writer.Write(role);
                    writer.Write(hasAvatar);
                    writer.Write(sendNotification);
                    writer.Write((short)status);
                }
                return m.ToArray();
            }
        }

        public bool hasRole(int index)
        {
            if(role.Contains(index + ";"))
            {
                return true;
            }
            return false;
        }

        public void setRole(int index)
        {
            if (index == 0)
            {
                role = "";
            }
            else
            {
                role = index + ";";
            }
        }

        public bool addRole(int index)
        {
            if (index == 0)
            {
                return false;
            }
            if (hasRole(index))
            {
                return false;
            }
            role += index + ";";
            return true;
        }

        public bool removeRole(int index)
        {
            if (index == 0)
            {
                return false;
            }
            if (!hasRole(index))
            {
                return false;
            }
            role.Replace(index + ";", "");
            return true;
        }

        public int getPrimaryRole()
        {
            if (role == "" || role == null)
            {
                return 0;
            }
            return Int32.Parse(role.Substring(0, role.IndexOf(';')));
        }
    }
}
