// <copyright file="Program.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Buffers.Text;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Mapping;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// RFC 7807 output application/problem+json
builder.Services.AddProblemDetails(options =>
{
    options.CustomizeProblemDetails = ctx =>
    {
        // additional info not part of RFC 7807
        ctx.ProblemDetails.Instance = ctx.HttpContext.Request.Path;
        ctx.ProblemDetails.Extensions["traceId"] = ctx.HttpContext.TraceIdentifier;
    };
});

// Logging config (optional, but recommended)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var connectionString = builder.Configuration.GetConnectionString("MeetlyOmniDb");

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string 'MeetlyOmniDb' is not configured.");
}

// PostgreSQL DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString));

// JWT Options Configuration
builder.Services.AddOptions<JwtOptions>(JwtOptions.SectionName)
        .BindConfiguration(JwtOptions.SectionName)
        .ValidateDataAnnotations()
        .ValidateOnStart();

// Identity Services
builder.Services.AddApplicationIdentity();

// JWT Key Provider
builder.Services.AddSingleton<IJwtKeyProvider, JwtKeyProvider>();

// JWT Authentication Configuration
builder.Services.AddJwtAuthentication(builder.Configuration);

// ---- Repositories ----

// ---- Application Services ----
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

// distribute exception handlers
builder.Services.AddExceptionHandler<NotFoundExceptionHandler>();
builder.Services.AddExceptionHandler<ValidationExceptionHandler>();
builder.Services.AddExceptionHandler<UnauthorizedExceptionHandler>();
builder.Services.AddExceptionHandler<ForbiddenExceptionHandler>();
builder.Services.AddExceptionHandler<ConflictExceptionHandler>();
builder.Services.AddExceptionHandler<GlobalUnhandledExceptionHandler>();

// Health Check
builder.Services.AddHealthChecks()
    .AddNpgSql(connectionString);

// CORS Configuration for cookie support
builder.Services.AddCorsWithCookieSupport();

builder.Services.AddControllers();

// Swagger Configuration
builder.Services.AddSwaggerWithJwtAuth();

// Register AutoMapper and scan for profiles starting from MappingProfile's assembly
builder.Services.AddAutoMapper(typeof(MappingProfile));

var app = builder.Build();

// Database initialization
await app.InitializeDatabaseAsync();

// Swagger
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Exception in different environments
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler();
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors();

// security headers
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    await next();
});

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
