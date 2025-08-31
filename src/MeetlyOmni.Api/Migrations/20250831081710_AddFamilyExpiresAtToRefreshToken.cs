// <copyright file="20250831081710_AddFamilyExpiresAtToRefreshToken.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MeetlyOmni.Api.Migrations;

/// <inheritdoc />
public partial class AddFamilyExpiresAtToRefreshToken : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "FamilyExpiresAt",
            table: "RefreshTokens",
            type: "timestamp with time zone",
            nullable: false,
            defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "FamilyExpiresAt",
            table: "RefreshTokens");
    }
}
