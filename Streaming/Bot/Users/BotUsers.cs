// Copyright (C) 2017-2026 Ixian
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

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.SpixiBot
{
    // TODO use a database for storing users. For now a workaround of last 500 users only will be stored due to memory constraints
    public class BotUsers
    {
        public OrderedDictionary<Address, BotContact> contacts = new OrderedDictionary<Address, BotContact>(new AddressComparer());

        string contactsPath = "contacts.ixi";
        string? avatarPath = "Avatars";
        bool saveNickAsString = false;

        public BotUsers(string contacts_path, string? avatar_path, bool save_nick_as_string)
        {
            saveNickAsString = save_nick_as_string;
            contactsPath = contacts_path;
            if (avatar_path != null)
            {
                if (!Directory.Exists(avatar_path))
                {
                    Directory.CreateDirectory(avatar_path);
                }
            }
            avatarPath = avatar_path;
        }

        public void writeContactsToFile()
        {
            lock (contacts)
            {
                FileStream fs;
                BinaryWriter writer;
                try
                {
                    // Prepare the file for writing
                    fs = new FileStream(contactsPath, FileMode.Create);
                    writer = new BinaryWriter(fs);
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", contactsPath, e.Message);
                    return;
                }

                try
                {
                    int version = 1;
                    writer.Write(version);

                    writer.Write(false); // Can be reused in the future

                    int num_contacts = contacts.Count;
                    writer.Write(num_contacts);

                    foreach (var contact in contacts)
                    {
                        var contact_info = contact.Value;
                        if (contact_info == null)
                        {
                            continue;
                        }
                        byte[] contact_bytes = contact_info.getBytes(saveNickAsString);
                        writer.Write(contact_bytes.Length);
                        writer.Write(contact_bytes);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot write to {0} file: {1}", contactsPath, e.Message);
                }
                writer.Flush();
                writer.Close();
                writer.Dispose();

                fs.Close();
                fs.Dispose();
            }
        }

        public void loadContactsFromFile()
        {
            if (File.Exists(contactsPath) == false)
            {
                return;
            }

            lock (contacts)
            {
                BinaryReader reader;
                try
                {
                    reader = new BinaryReader(new FileStream(contactsPath, FileMode.Open));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot open {0} file: {1}", contactsPath, e.Message);
                    return;
                }

                try
                {
                    int version = reader.ReadInt32();

                    if (version > 0)
                    {
                        reader.ReadBoolean(); // Can be reused in the future
                    }

                    int num_contacts = reader.ReadInt32();
                    for (int i = 0; i < num_contacts; i++)
                    {
                        int contact_len = reader.ReadInt32();
                        byte[] contact_bytes = reader.ReadBytes(contact_len);

                        BotContact bc = new BotContact(contact_bytes, saveNickAsString);
                        Address address = new Address(bc.publicKey);
                        contacts.AddOrReplace(address, bc);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot read from {0} file: {1}", contactsPath, e.Message);
                    // TODO TODO notify the user or something like that
                }

                reader.Close();
            }
        }

        public Address getOwner()
        {
            lock (contacts)
            {
                return contacts.First().Key;
            }
        }

        public bool hasUser(Address address)
        {
            lock (contacts)
            {
                if (contacts.ContainsKey(address))
                {
                    return true;
                }
            }
            return false;
        }

        public BotContact? getUser(Address address)
        {
            lock (contacts)
            {
                if (contacts.ContainsKey(address))
                {
                    return contacts[address];
                }
            }
            return null;
        }

        public bool delUser(Address address)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts.Remove(address);
                writeContactsToFile();
            }
            return true;
        }

        public bool setPubKey(Address address, byte[]? pub_key, bool limit = true)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    contacts.Add(address, new BotContact(null, pub_key, 0, false));
                    // TODO temporary limit, should be removed after switching to db
                    if (limit && contacts.Count > 500)
                    {
                        contacts.Remove(address);
                    }
                    writeContactsToFile();
                }
            }
            return true;
        }

        public bool setAvatar(Address address, byte[] avatar_message)
        {
            if (avatarPath == null)
            {
                throw new Exception("Cannot set avatar, avatarPath is null.");
            }
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                string path = Path.Combine(avatarPath, address.ToString() + ".raw");
                if (avatar_message != null)
                {
                    File.WriteAllBytes(path, avatar_message);
                    getUser(address).hasAvatar = true;
                }
                else
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                    }
                    getUser(address).hasAvatar = false;
                }
                writeContactsToFile();
            }
            return true;
        }

        public bool setNick(Address address, byte[] nick)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts[address].setNick(nick);
                writeContactsToFile();
            }
            return true;
        }

        public bool setRole(Address address, int role)
        {
            lock (contacts)
            {
                if (!hasUser(address))
                {
                    return false;
                }
                contacts[address].setRole(role);
                writeContactsToFile();
            }
            return true;
        }

        public void setUser(BotContact user, bool limit = true)
        {
            lock (contacts)
            {
                Address address = new Address(user.publicKey);
                contacts.AddOrReplace(address, user);
                // TODO temporary limit, should be removed after switching to db
                if (limit && contacts.Count > 500)
                {
                    contacts.Remove(contacts.First().Key);
                }
                writeContactsToFile();
            }
        }

        public void clearUsers()
        {
            lock (contacts)
            {
                contacts.Clear();
                writeContactsToFile();
            }
        }

        public string? getAvatarPath(Address address)
        {
            if (avatarPath == null)
            {
                throw new Exception("Cannot get avatar path, avatarPath is null.");
            }

            if (!hasUser(address))
            {
                return null;
            }
            string path = Path.Combine(avatarPath, address.ToString() + ".raw");
            if (!File.Exists(path))
            {
                return null;
            }
            return path;
        }

        public int count()
        {
            lock (contacts)
            {
                return contacts.Count;
            }
        }
    }
}
