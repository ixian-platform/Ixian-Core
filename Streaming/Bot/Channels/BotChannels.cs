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

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.SpixiBot
{
    public class BotChannels
    {
        public Dictionary<string, BotChannel> channels = new Dictionary<string, BotChannel>();

        string channelsPath = "channels.ixi";

        public BotChannels(string channels_path)
        {
            channelsPath = channels_path;
        }

        public void writeChannelsToFile()
        {
            lock (channels)
            {
                FileStream fs;
                BinaryWriter writer;
                try
                {
                    // Prepare the file for writing
                    fs = new FileStream(channelsPath, FileMode.Create);
                    writer = new BinaryWriter(fs);
                }
                catch (Exception e)
                {
                    Logging.error("Cannot create {0} file: {1}", channelsPath, e.Message);
                    return;
                }

                try
                {
                    int version = 0;
                    writer.Write(version);

                    int num_channels = channels.Count;
                    writer.Write(num_channels);

                    foreach (var channel in channels)
                    {
                        byte[] channel_bytes = channel.Value.getBytes();
                        writer.Write(channel_bytes.Length);
                        writer.Write(channel_bytes);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot write to {0} file: {1}", channelsPath, e.Message);
                }
                writer.Flush();
                writer.Close();
                writer.Dispose();

                fs.Close();
                fs.Dispose();
            }
        }

        public void loadChannelsFromFile()
        {
            if (File.Exists(channelsPath) == false)
            {
                return;
            }

            lock (channels)
            {
                BinaryReader reader;
                try
                {
                    reader = new BinaryReader(new FileStream(channelsPath, FileMode.Open));
                }
                catch (Exception e)
                {
                    Logging.error("Cannot open {0} file: {1}", channelsPath, e.Message);
                    return;
                }

                try
                {
                    int version = reader.ReadInt32();

                    int num_channels = reader.ReadInt32();
                    for (int i = 0; i < num_channels; i++)
                    {
                        int channel_len = reader.ReadInt32();
                        byte[] channel_bytes = reader.ReadBytes(channel_len);

                        BotChannel bc = new BotChannel(channel_bytes);
                        channels.AddOrReplace(bc.channelName, bc);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Cannot read from {0} file: {1}", channelsPath, e.Message);
                    // TODO TODO notify the user or something like that
                }

                reader.Close();
            }
        }

        public bool hasChannel(string name)
        {
            lock (channels)
            {
                if (channels.ContainsKey(name))
                {
                    return true;
                }
            }
            return false;
        }

        public bool hasChannel(int index)
        {
            if(index == 0)
            {
                return true;
            }
            lock (channels)
            {
                string str = channelIndexToName(index);
                if (str == null)
                {
                    return false;
                }
                if (str == "")
                {
                    return true;
                }
                return hasChannel(str);
            }
        }

        public BotChannel getChannel(int index)
        {
            if (index == 0)
            {
                return null;
            }
            lock (channels)
            {
                string str = channelIndexToName(index);
                if (str == null)
                {
                    return null;
                }
                if (str == "")
                {
                    return null;
                }
                return getChannel(str);
            }
        }


        public BotChannel getChannel(string name)
        {
            lock (channels)
            {
                if (channels.ContainsKey(name))
                {
                    return channels[name];
                }
            }
            return null;
        }

        public bool setChannel(string name, BotChannel channel)
        {
            lock (channels)
            {
                if (channel == null)
                {
                    if (channels.ContainsKey(name))
                    {
                        channels.Remove(name);
                    }
                }
                else
                {
                    if (hasChannel(name))
                    {
                        channels.Remove(name);
                    }
                    if(hasChannel(channel.index))
                    {
                        channels.Remove(channelIndexToName(channel.index));
                    }
                    channels.AddOrReplace(channel.channelName, channel);
                }
                writeChannelsToFile();
            }
            return true;
        }

        public int getNextIndex()
        {
            lock (channels)
            {
                if (channels.Count > 0)
                {
                    return channels.Last().Value.index + 1;
                }
            }
            return 1;
        }

        public string channelIndexToName(int id)
        {
            if (id == 0)
            {
                return "";
            }
            lock (channels)
            {
                try
                {
                    var channel = channels.FirstOrDefault(x => x.Value.index == id);
                    return channel.Key;
                }catch(Exception e)
                {
                    Logging.error("Error getting channel with id {0}: {1}", id, e);
                }
                return null;
            }
        }

        public int count()
        {
            lock (channels)
            {
                return channels.Count;
            }
        }

        public void clear()
        {
            lock (channels)
            {
                channels.Clear();
            }
        }
    }
}
