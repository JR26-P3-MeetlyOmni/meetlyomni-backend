// <copyright file="AWSOptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;

namespace MeetlyOmni.Api.Common.Options
{
    public class AWSOptions
    {
        public AWSCredentials Credentials { get; set; }
        public RegionEndpoint Region { get; set; }
        public string BucketName { get; set; }

        /// <summary>
        /// Initialize AWSOptions from a specified AWS profile.
        /// Supports regular IAM profiles and SSO profiles.
        /// </summary>
        /// <param name="profileName">The AWS profile name</param>
        /// <param name="region">The AWS region, e.g. "ap-southeast-2"</param>
        /// <param name="bucketName">The S3 bucket name</param>
        /// <returns>An AWSOptions instance</returns>
        public static AWSOptions FromProfile(string profileName, string region, string bucketName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                throw new ArgumentException("profileName cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(region))
                throw new ArgumentException("region cannot be null or empty.");

            var chain = new CredentialProfileStoreChain();

            try
            {
                if (!chain.TryGetAWSCredentials(profileName, out var credentials))
                {
                    throw new InvalidOperationException(
                        $"Unable to get credentials for AWS profile '{profileName}'. " +
                        $"If this is an SSO profile, run 'aws sso login --profile {profileName}'.");
                }

                return new AWSOptions
                {
                    Credentials = credentials,
                    Region = RegionEndpoint.GetBySystemName(region),
                    BucketName = bucketName
                };
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Failed to initialize AWSOptions. Please check your ~/.aws/config and ~/.aws/credentials files. Profile '{profileName}' may not exist or be invalid. Original error: {ex.Message}", ex);
            }
        }
    }
}



