// <copyright file="AWSOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;

using Amazon;
using Amazon.Runtime;

namespace MeetlyOmni.Api.Common.Options;

public class AWSOptions
{
    public RegionEndpoint Region { get; set; }

    public string BucketName { get; set; }

    public AWSCredentials Credentials { get; set; } = null;

    public static AWSOptions Create(string region, string bucketName)
    {
        if (string.IsNullOrWhiteSpace(region)) throw new ArgumentException("Region is required", nameof(region));
        if (string.IsNullOrWhiteSpace(bucketName)) throw new ArgumentException("BucketName is required", nameof(bucketName));

        return new AWSOptions
        {
            Region = RegionEndpoint.GetBySystemName(region),
            BucketName = bucketName,
            Credentials = null
        };
    }
}
