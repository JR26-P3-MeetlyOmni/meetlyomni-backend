// <copyright file="AWSOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Amazon;
using Amazon.Runtime;

namespace MeetlyOmni.Api.Common.Options
{
    public class AWSOptions
    {
        public AWSCredentials Credentials { get; set; }
        public RegionEndpoint Region { get; set; }
        public string BucketName { get; set; } // Add this property to fix CS1061
    }
}
