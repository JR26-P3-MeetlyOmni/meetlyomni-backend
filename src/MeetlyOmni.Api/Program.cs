// <copyright file="Program.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.IdentityModel.Tokens.Jwt;

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.S3;
using Amazon.SimpleEmailV2;

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
using MeetlyOmni.Api.Service.Email;
using MeetlyOmni.Api.Service.Email.Interfaces;
using MeetlyOmni.Api.Service.EventService;
using MeetlyOmni.Api.Service.EventService.Interfaces;
using MeetlyOmni.Api.Service.Invitation;
using MeetlyOmni.Api.Service.Invitation.Interfaces;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using Npgsql;

var builder = default(WebApplicationBuilder);

try
{
    // Wrap CreateBuilder to provide clearer diagnostics when configuration files contain invalid JSON.
    builder = WebApplication.CreateBuilder(args);
}
catch (InvalidDataException ex)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("ERROR: Failed to load configuration files during application startup.");
    Console.Error.WriteLine("Reason: " + ex.Message);

    // Print inner exception details (often contains JSON parsing errors)
    if (ex.InnerException is not null)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine("Inner exception details:");
        Console.Error.WriteLine(ex.InnerException.ToString());
    }

    Console.Error.WriteLine();
    Console.Error.WriteLine("Please fix the JSON syntax in your appsettings*.json files (see stack trace above).");
    Console.Error.WriteLine("Exiting with code 1.");
    Environment.Exit(1);
    throw; // unreachable, but keeps compiler happy
}

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
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SameOrganization", policy =>
        policy.Requirements.Add(new MeetlyOmni.Api.Authorization.Requirements.SameOrganizationRequirement()));
});

// Register authorization handlers
builder.Services.AddScoped<Microsoft.AspNetCore.Authorization.IAuthorizationHandler,
    MeetlyOmni.Api.Authorization.Handlers.SameOrganizationAuthorizationHandler<MeetlyOmni.Api.Data.Entities.Event>>();

// ---- Repositories ----
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IEventRepository, EventRepository>();
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<IOrganizationRepository, OrganizationRepository>();

// ---- Application Services ----
builder.Services.AddScoped<ILoginService, LoginService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ILogoutService, LogoutService>();
builder.Services.AddScoped<ISignUpService, SignUpService>();
builder.Services.AddScoped<IResetPasswordService, ResetPasswordService>();
builder.Services.AddScoped<IEventService, EventService>();
builder.Services.AddScoped<IInvitationService, InvitationService>();

// ---- Common Services ----
builder.Services.AddScoped<IClientInfoService, ClientInfoService>();

// Email Services
builder.Services.AddSingleton<IEmailTemplateService, EmailTemplateService>();
builder.Services.AddSingleton<IEmailSender, AwsSesEmailSender>();
builder.Services.AddScoped<IEmailLinkService, EmailLinkService>();
builder.Services.AddScoped<AccountMailer>();
builder.Services.AddSingleton<IAmazonSimpleEmailServiceV2>(sp =>
    new AmazonSimpleEmailServiceV2Client(RegionEndpoint.APSoutheast2));

// Global exception handling is now handled by middleware

// Health Check
builder.Services.AddHealthChecks()
    .AddNpgSql(connectionString);

builder.Services.AddCorsWithCookieSupport(builder.Configuration);

// ForwardedHeaders configuration for ALB HTTPS termination
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto |
                               ForwardedHeaders.XForwardedHost;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.IsEssential = true;
    options.Cookie.Path = AuthCookieExtensions.CookiePaths.Root;

    if (builder.Environment.IsProduction())
    {
        options.Cookie.Domain = ".meetlyomni.com";
    }
});

if (builder.Environment.IsProduction())
{
    MeetlyOmni.Api.Common.Extensions.AuthCookieExtensions
        .ConfigureCookieDomain(".meetlyomni.com");
}
else
{
    MeetlyOmni.Api.Common.Extensions.AuthCookieExtensions
        .ConfigureCookieDomain(null);
}

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

// Amazon S3 Configuration
var awsSection = builder.Configuration.GetSection("AWS");
var isCi = Environment.GetEnvironmentVariable("CI") == "true";
var profileName = awsSection["Profile"] ?? (isCi ? string.Empty : throw new InvalidOperationException("AWS:Profile is not configured."));
var region = awsSection["Region"] ?? (isCi ? string.Empty : throw new InvalidOperationException("AWS:Region is not configured."));
var bucketName = awsSection["BucketName"] ?? (isCi ? string.Empty : throw new InvalidOperationException("AWS:BucketName is not configured."));

Console.WriteLine($"AWS Profile: {profileName}");
Console.WriteLine($"AWS Region: {region}");
Console.WriteLine($"AWS Bucket: {bucketName}");

if (isCi && (string.IsNullOrEmpty(profileName) || string.IsNullOrEmpty(region) || string.IsNullOrEmpty(bucketName)))
{
    Console.WriteLine("Running in CI: skipping AWS initialization.");
}

// Initialize AWSOptions using the profile
var awsOptions = AWSOptions.FromProfile(profileName, region, bucketName);

// Register AWSOptions and S3 client in DI
builder.Services.AddSingleton(awsOptions);
builder.Services.AddSingleton<IAmazonS3>(sp =>
{
    var options = sp.GetRequiredService<AWSOptions>();
    return new AmazonS3Client(options.Credentials, options.Region);
});

builder.Services.AddControllers();

var app = builder.Build();

// Database initialization
await app.InitializeDatabaseAsync();

// Early pipeline: ForwardedHeaders -> GlobalException
app.UseForwardedHeaders();
app.UseGlobalExceptionHandler();

// Swagger
app.UseSwaggerWithApiVersioning();

// Use framework built-in HTTPS redirection (works correctly with UseForwardedHeaders)
app.UseHttpsRedirection();

// No-cache middleware for authentication endpoints
app.UseNoCache();

// Routing must come before CORS/Auth
app.UseRouting();

// CORS before Auth/Authorization
app.UseCors();

// Security headers (after routing, before auth)
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

// Antiforgery protection (after auth, before endpoints)
app.UseAntiforgeryProtection();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
