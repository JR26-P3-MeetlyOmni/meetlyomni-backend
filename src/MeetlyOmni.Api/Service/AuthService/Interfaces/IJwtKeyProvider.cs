// <copyright file="IJwtKeyProvider.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using Microsoft.IdentityModel.Tokens;

namespace MeetlyOmni.Api.Service.AuthService.Interfaces;

public interface IJwtKeyProvider
{
    SecurityKey GetSigningKey();

    SecurityKey GetValidationKey();
}
