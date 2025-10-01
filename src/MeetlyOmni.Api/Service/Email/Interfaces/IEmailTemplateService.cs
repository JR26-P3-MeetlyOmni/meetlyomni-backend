// <copyright file="IEmailTemplateService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Enums.EmailType;
using MeetlyOmni.Api.Models.Email;

namespace MeetlyOmni.Api.Service.Email.Interfaces;

public interface IEmailTemplateService
{
    EmailMessage Build(EmailType type, string to, IDictionary<string, string> data);
}
