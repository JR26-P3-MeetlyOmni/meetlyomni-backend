// <copyright file="SkipAntiforgeryAttribute.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Middlewares.Antiforgery;

/// <summary>
/// Attribute to skip antiforgery validation for specific controllers or actions.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipAntiforgeryAttribute : Attribute
{
}
