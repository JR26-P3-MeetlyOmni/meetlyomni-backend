// <copyright file="Program.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Buffers.Text;
using System.IdentityModel.Tokens.Jwt;

using Asp.Versioning;
using Asp.Versioning.ApiExplorer;

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Mapping;
using MeetlyOmni.Api.Middlewares.Antiforgery;
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
builder.Services.Configure<IdentityOptions>(options =>
{
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -._@+";
});

// JWT Key Provider
builder.Services.AddSingleton<IJwtKeyProvider, JwtKeyProvider>();

// JWT Authentication Configuration
builder.Services.AddJwtAuthentication(builder.Configuration);

// Authorization services (required for [Authorize])
builder.Services.AddAuthorization();

// ---- Repositories ----
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<IOrganizationRepository, OrganizationRepository>();

// ---- Application Services ----
builder.Services.AddScoped<ILoginService, LoginService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ILogoutService, LogoutService>();
builder.Services.AddScoped<ISignUpService, SignUpService>();

// ---- Common Services ----
builder.Services.AddScoped<IClientInfoService, ClientInfoService>();

// Global exception handling is now handled by middleware

// Health Check
builder.Services.AddHealthChecks()
    .AddNpgSql(connectionString);

// CORS Configuration for cookie support
builder.Services.AddCorsWithCookieSupport();

// Antiforgery Configuration for CSRF protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.IsEssential = true;
    options.Cookie.Path = AuthCookieExtensions.CookiePaths.Root;
});

// API Versioning Configuration
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader(),
        new HeaderApiVersionReader("X-API-Version"),
        new MediaTypeApiVersionReader("version"));
})
.AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV"; // v1, v2
    options.SubstituteApiVersionInUrl = true;
});

// Swagger Configuration with API versioning
builder.Services.AddSwaggerWithApiVersioning();

// Register AutoMapper and scan for profiles starting from MappingProfile's assembly
builder.Services.AddAutoMapper(typeof(MappingProfile));

// Antiforgery options binding (must be registered before building the app)
builder.Services.Configure<AntiforgeryProtectionOptions>(
    builder.Configuration.GetSection("AntiforgeryProtection"));

var app = builder.Build();

// Database initialization
await app.InitializeDatabaseAsync();

// Global exception handling middleware (placed early in pipeline to catch all exceptions)
app.UseGlobalExceptionHandler();

// Swagger
if (app.Environment.IsDevelopment())
{
    app.UseSwaggerWithApiVersioning();
}

app.UseHttpsRedirection();

// No-cache middleware for authentication endpoints
app.UseNoCache();

// Enable CORS
app.UseCors();

// Antiforgery protection (must be before authentication)
app.UseAntiforgeryProtection();

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
