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

using System.Collections.Generic;

namespace IXICore.Activity
{
    public interface IActivityStorage
    {
        public abstract bool prepareStorage(bool optimize);
        public abstract void stopStorage();
        public abstract void deleteData();

        public abstract List<ActivityObject> getActivitiesBySeedHashAndType(byte[] seedHash, ActivityType? type, byte[] fromActivityId = null, int count = 0, bool descending = false);

        public abstract bool insertActivity(ActivityObject activity);

        public abstract bool updateStatus(byte[] id, ActivityStatus status, ulong blockHeight, long timestamp = 0);
        public abstract bool updateValue(byte[] id, IxiNumber value);

    }
}