// <copyright file="DomainExceptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Collections.ObjectModel;

// <copyright file="DomainExceptions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>
namespace MeetlyOmni.Api.Filters;

public sealed class EntityNotFoundException : Exception
{
    public EntityNotFoundException(string? resource, string? key, string? message = null)
        : base(message ?? "Resource not found.")
    {
        Resource = resource;
        Key = key;
    }

    public string? Resource { get; }

    public string? Key { get; }
}

public sealed class DomainValidationException : Exception
{
    public DomainValidationException(IReadOnlyDictionary<string, string[]> errors, string? message = null)
        : base(message ?? "One or more validation errors occurred.")
    {
        ArgumentNullException.ThrowIfNull(errors);
        Errors = new ReadOnlyDictionary<string, string[]>(new Dictionary<string, string[]>(errors));
    }

    public IReadOnlyDictionary<string, string[]> Errors { get; }
}

public sealed class UnauthorizedAppException : Exception
{
    public UnauthorizedAppException(string? message = null)
        : base(message ?? "Unauthorized.")
    {
    }
}

public sealed class ForbiddenAppException : Exception
{
    public ForbiddenAppException(string? message = null)
        : base(message ?? "Forbidden.")
    {
    }
}

public sealed class ConflictAppException : Exception
{
    public ConflictAppException(string? message = null)
        : base(message ?? "Conflict.")
    {
    }
}
