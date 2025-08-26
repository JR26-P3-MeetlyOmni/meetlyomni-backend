// <copyright file="Program.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Extensions;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Organization;
using MeetlyOmni.Api.Mapping;
using MeetlyOmni.Api.Service.SignUpService;

using Microsoft.EntityFrameworkCore;

using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// Logging config (optional, but recommended)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var connectionString = builder.Configuration.GetConnectionString("MeetlyOmniDb");

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string 'MeetlyOmniDb' is not configured.");
}

var dsBuilder = new NpgsqlDataSourceBuilder(connectionString);
dsBuilder.EnableDynamicJson();

var dataSource = dsBuilder.Build();

// PostgreSQL DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(dataSource));

// Identity Services
builder.Services.AddApplicationIdentity();

// Health Check
builder.Services.AddHealthChecks()
    .AddNpgSql(connectionString);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<IOrganizationRepository, OrganizationRepository>();
builder.Services.AddScoped<ISignUpService, SignUpService>();

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

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
