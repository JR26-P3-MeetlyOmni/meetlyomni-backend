// <copyright file="SystemsManagerXmlRepository.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Linq;
using System.Xml.Linq;

using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;

using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;

namespace MeetlyOmni.Api.Common.DataProtection;

public sealed class SystemsManagerXmlRepository : IXmlRepository
{
    private const string RootElementName = "repository";

    private readonly IAmazonSimpleSystemsManagement _systemsManager;
    private readonly string _parameterName;
    private readonly ILogger<SystemsManagerXmlRepository> _logger;

    public SystemsManagerXmlRepository(
        IAmazonSimpleSystemsManagement systemsManager,
        string parameterName,
        ILogger<SystemsManagerXmlRepository> logger)
    {
        _systemsManager = systemsManager ?? throw new ArgumentNullException(nameof(systemsManager));
        _parameterName = string.IsNullOrWhiteSpace(parameterName)
            ? throw new ArgumentException("Parameter name must be provided.", nameof(parameterName))
            : parameterName;
        _logger = logger;
    }

    private static XDocument CreateEmptyDocument() =>
        new(new XElement(RootElementName));

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        try
        {
            var document = LoadDocument();
            var root = document.Root;

            if (root is null)
            {
                return Array.Empty<XElement>();
            }

            return root.Elements().Select(e => new XElement(e)).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load data-protection keys from SSM parameter '{ParameterName}'.", _parameterName);
            throw;
        }
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        if (element is null)
        {
            throw new ArgumentNullException(nameof(element));
        }

        try
        {
            var document = LoadDocument();
            var keyElement = new XElement(element);

            if (!string.IsNullOrWhiteSpace(friendlyName))
            {
                keyElement.SetAttributeValue("friendlyName", friendlyName);
            }

            document.Root!.Add(keyElement);

            var payload = document.ToString(SaveOptions.DisableFormatting);

            var request = new PutParameterRequest
            {
                Name = _parameterName,
                Value = payload,
                Type = ParameterType.SecureString,
                Overwrite = true,
            };

            _systemsManager.PutParameterAsync(request).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist data-protection key to SSM parameter '{ParameterName}'.", _parameterName);
            throw;
        }
    }

    private XDocument LoadDocument()
    {
        try
        {
            var response = _systemsManager.GetParameterAsync(new GetParameterRequest
            {
                Name = _parameterName,
                WithDecryption = true,
            }).GetAwaiter().GetResult();

            var value = response.Parameter?.Value;

            if (string.IsNullOrWhiteSpace(value))
            {
                return CreateEmptyDocument();
            }

            return XDocument.Parse(value);
        }
        catch (ParameterNotFoundException)
        {
            _logger.LogInformation(
                "SSM parameter '{ParameterName}' was not found. A new parameter will be created on first key rotation.",
                _parameterName);
            return CreateEmptyDocument();
        }
    }
}
