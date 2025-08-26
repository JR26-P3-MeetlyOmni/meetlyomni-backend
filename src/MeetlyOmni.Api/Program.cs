// <copyright file="Program.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Buffers.Text;
using System.IdentityModel.Tokens.Jwt;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Mapping;
using MeetlyOmni.Api.Service.AuthService;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Common;
using MeetlyOmni.Api.Service.Common.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// Clear default JWT claim mappings to use standard claim names
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

// Logging config (optional, but recommended)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var connectionString = builder.Configuration.GetConnectionString("MeetlyOmniDb");

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string 'MeetlyOmniDb' is not configured.");
}

// setup DataSource and start using Dynamic JSONS
var dsBuilder = new NpgsqlDataSourceBuilder(connectionString);

// key point, start Dynamic  JSON
dsBuilder.EnableDynamicJson();

var dataSource = dsBuilder.Build();

// ---- DbContext ----
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(dataSource));

// JWT Options Configuration
builder.Services.AddOptions<JwtOptions>()
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
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

// ---- Application Services ----
builder.Services.AddScoped<ILoginService, LoginService>();
builder.Services.AddScoped<ITokenService, TokenService>();

// ---- Common Services ----
builder.Services.AddScoped<IClientInfoService, ClientInfoService>();

// Health Check
builder.Services.AddHealthChecks()
    .AddNpgSql(connectionString);

// CORS Configuration for cookie support
builder.Services.AddCorsWithCookieSupport();

// Antiforgery Configuration for CSRF protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.Path = AuthCookieExtensions.CookiePaths.TokenApi;
});

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

app.UseHttpsRedirection();

// Enable CORS
app.UseCors();

// Antiforgery middleware (must be before authentication)
app.UseAntiforgery();

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
