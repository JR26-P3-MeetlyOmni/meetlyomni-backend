// <copyright file="AWSOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;

namespace MeetlyOmni.Api.Common.Options;

public class AWSOptions
{
    public AWSCredentials Credentials { get; set; }

    public RegionEndpoint Region { get; set; }

    public string BucketName { get; set; }

    /// <summary>
    /// Initialize AWSOptions from a specified AWS profile.
    /// Supports regular IAM profiles and SSO profiles.
    /// </summary>
    /// <param name="profileName">The AWS profile name.</param>
    /// <param name="region">The AWS region, e.g. "ap-southeast-2".</param>
    /// <param name="bucketName">The S3 bucket name.</param>
    /// <returns>An AWSOptions instance.</returns>
    public static AWSOptions FromProfile(string profileName, string region, string bucketName)
    {
        try
        {
            var chain = new CredentialProfileStoreChain();
            if (chain.TryGetAWSCredentials(profileName, out var credentials))
            {
                return new AWSOptions
                {
                    Credentials = credentials,
                    Region = Amazon.RegionEndpoint.GetBySystemName(region),
                    BucketName = bucketName,
                };
            }

            // Fallback: try environment variables
            var envCredentials = new EnvironmentVariablesAWSCredentials();

            // Try to get credentials from environment variables (throws if not found)
            var creds = envCredentials.GetCredentials();
            return new AWSOptions
            {
                Credentials = envCredentials,
                Region = Amazon.RegionEndpoint.GetBySystemName(region),
                BucketName = bucketName,
            };
        }
        catch (Exception ex)
        {
            // Fallback: use default profile if available
            var chain = new CredentialProfileStoreChain();
            if (chain.TryGetAWSCredentials("default", out var defaultCredentials))
            {
                return new AWSOptions
                {
                    Credentials = defaultCredentials,
                    Region = Amazon.RegionEndpoint.GetBySystemName(region),
                    BucketName = bucketName,
                };
            }

            // Fallback: use anonymous credentials for local/mock/test
            return new AWSOptions
            {
                Credentials = new AnonymousAWSCredentials(),
                Region = Amazon.RegionEndpoint.GetBySystemName(region),
                BucketName = bucketName,
            };
        }
    }
}
