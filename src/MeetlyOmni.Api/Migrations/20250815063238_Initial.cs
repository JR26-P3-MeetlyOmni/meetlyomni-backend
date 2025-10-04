// <copyright file="20250815063238_Initial.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;

using Microsoft.EntityFrameworkCore.Migrations;

using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace MeetlyOmni.Api.Migrations;

/// <inheritdoc />
public partial class Initial : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;");
        migrationBuilder.CreateTable(
            name: "AspNetRoles",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                NormalizedName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                ConcurrencyStamp = table.Column<string>(type: "text", nullable: false, defaultValueSql: "gen_random_uuid()::text"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetRoles", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Organizations",
            columns: table => new
            {
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                OrganizationCode = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                OrganizationName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                LogoUrl = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                CoverImageUrl = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Location = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                WebsiteUrl = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                IndustryTags = table.Column<List<string>>(type: "jsonb", nullable: true, defaultValueSql: "'[]'::jsonb"),
                FollowerCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                IsVerified = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                PlanType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Free"),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Organizations", x => x.OrgId);
            });

        migrationBuilder.CreateTable(
            name: "AspNetRoleClaims",
            columns: table => new
            {
                Id = table.Column<int>(type: "integer", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                RoleId = table.Column<Guid>(type: "uuid", nullable: false),
                ClaimType = table.Column<string>(type: "text", nullable: true),
                ClaimValue = table.Column<string>(type: "text", nullable: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                table.ForeignKey(
                    name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "AspNetRoles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AspNetUsers",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                LocalMemberNumber = table.Column<int>(type: "integer", nullable: false),
                LanguagePref = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                Tags = table.Column<List<string>>(type: "jsonb", nullable: false, defaultValueSql: "'[]'::jsonb"),
                Points = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Active"),
                LastLogin = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                UserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                NormalizedUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                NormalizedEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                EmailConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                PasswordHash = table.Column<string>(type: "text", nullable: true),
                SecurityStamp = table.Column<string>(type: "text", nullable: true),
                ConcurrencyStamp = table.Column<string>(type: "text", nullable: true),
                PhoneNumber = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                PhoneNumberConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                TwoFactorEnabled = table.Column<bool>(type: "boolean", nullable: false),
                LockoutEnd = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                LockoutEnabled = table.Column<bool>(type: "boolean", nullable: false),
                AccessFailedCount = table.Column<int>(type: "integer", nullable: false),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                table.ForeignKey(
                    name: "FK_AspNetUsers_Organizations_OrgId",
                    column: x => x.OrgId,
                    principalTable: "Organizations",
                    principalColumn: "OrgId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "Event",
            columns: table => new
            {
                EventId = table.Column<Guid>(type: "uuid", nullable: false),
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                Title = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Description = table.Column<string>(type: "text", nullable: true),
                CoverImageUrl = table.Column<string>(type: "text", nullable: true),
                StartTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                EndTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                Location = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Language = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: true),
                Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Draft"),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Event", x => x.EventId);
                table.ForeignKey(
                    name: "FK_Event_Organizations_OrgId",
                    column: x => x.OrgId,
                    principalTable: "Organizations",
                    principalColumn: "OrgId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AspNetUserClaims",
            columns: table => new
            {
                Id = table.Column<int>(type: "integer", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                UserId = table.Column<Guid>(type: "uuid", nullable: false),
                ClaimType = table.Column<string>(type: "text", nullable: true),
                ClaimValue = table.Column<string>(type: "text", nullable: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                table.ForeignKey(
                    name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AspNetUserLogins",
            columns: table => new
            {
                LoginProvider = table.Column<string>(type: "text", nullable: false),
                ProviderKey = table.Column<string>(type: "text", nullable: false),
                ProviderDisplayName = table.Column<string>(type: "text", nullable: true),
                UserId = table.Column<Guid>(type: "uuid", nullable: false),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                table.ForeignKey(
                    name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AspNetUserRoles",
            columns: table => new
            {
                UserId = table.Column<Guid>(type: "uuid", nullable: false),
                RoleId = table.Column<Guid>(type: "uuid", nullable: false),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                table.ForeignKey(
                    name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "AspNetRoles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AspNetUserTokens",
            columns: table => new
            {
                UserId = table.Column<Guid>(type: "uuid", nullable: false),
                LoginProvider = table.Column<string>(type: "text", nullable: false),
                Name = table.Column<string>(type: "text", nullable: false),
                Value = table.Column<string>(type: "text", nullable: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                table.ForeignKey(
                    name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "Game",
            columns: table => new
            {
                GameId = table.Column<Guid>(type: "uuid", nullable: false),
                Type = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                Title = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Config = table.Column<JsonObject>(type: "jsonb", nullable: true),
                CreatedBy = table.Column<Guid>(type: "uuid", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Game", x => x.GameId);
                table.ForeignKey(
                    name: "FK_Game_AspNetUsers_CreatedBy",
                    column: x => x.CreatedBy,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateTable(
            name: "MemberActivityLogs",
            columns: table => new
            {
                LogId = table.Column<Guid>(type: "uuid", nullable: false),
                MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                EventType = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false),
                EventDetail = table.Column<JsonObject>(type: "jsonb", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_MemberActivityLogs", x => x.LogId);
                table.ForeignKey(
                    name: "FK_MemberActivityLogs_AspNetUsers_MemberId",
                    column: x => x.MemberId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_MemberActivityLogs_Organizations_OrgId",
                    column: x => x.OrgId,
                    principalTable: "Organizations",
                    principalColumn: "OrgId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "RaffleTickets",
            columns: table => new
            {
                TicketId = table.Column<Guid>(type: "uuid", nullable: false),
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                IssuedBy = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                Status = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false, defaultValue: "Unused"),
                IssueTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RaffleTickets", x => x.TicketId);
                table.ForeignKey(
                    name: "FK_RaffleTickets_AspNetUsers_MemberId",
                    column: x => x.MemberId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_RaffleTickets_Organizations_OrgId",
                    column: x => x.OrgId,
                    principalTable: "Organizations",
                    principalColumn: "OrgId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "EventContentBlock",
            columns: table => new
            {
                BlockId = table.Column<Guid>(type: "uuid", nullable: false),
                EventId = table.Column<Guid>(type: "uuid", nullable: false),
                BlockType = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                Title = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Content = table.Column<JsonObject>(type: "jsonb", nullable: true),
                OrderNum = table.Column<int>(type: "integer", nullable: true, defaultValue: 0),
                Visible = table.Column<bool>(type: "boolean", nullable: true, defaultValue: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EventContentBlock", x => x.BlockId);
                table.ForeignKey(
                    name: "FK_EventContentBlock_Event_EventId",
                    column: x => x.EventId,
                    principalTable: "Event",
                    principalColumn: "EventId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "Guest",
            columns: table => new
            {
                GuestId = table.Column<Guid>(type: "uuid", nullable: false),
                EventId = table.Column<Guid>(type: "uuid", nullable: false),
                Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                AvatarUrl = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Bio = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Company = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Position = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                SocialLinks = table.Column<JsonObject>(type: "jsonb", nullable: true),
                Order = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Guest", x => x.GuestId);
                table.ForeignKey(
                    name: "FK_Guest_Event_EventId",
                    column: x => x.EventId,
                    principalTable: "Event",
                    principalColumn: "EventId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "EventGameInstance",
            columns: table => new
            {
                InstanceId = table.Column<Guid>(type: "uuid", nullable: false),
                EventId = table.Column<Guid>(type: "uuid", nullable: false),
                GameId = table.Column<Guid>(type: "uuid", nullable: false),
                TitleOverride = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Draft"),
                OrderNum = table.Column<int>(type: "integer", nullable: true),
                StartTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                EndTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EventGameInstance", x => x.InstanceId);
                table.ForeignKey(
                    name: "FK_EventGameInstance_Event_EventId",
                    column: x => x.EventId,
                    principalTable: "Event",
                    principalColumn: "EventId",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_EventGameInstance_Game_GameId",
                    column: x => x.GameId,
                    principalTable: "Game",
                    principalColumn: "GameId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "GameRecord",
            columns: table => new
            {
                RecordId = table.Column<Guid>(type: "uuid", nullable: false),
                InstanceId = table.Column<Guid>(type: "uuid", nullable: false),
                MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                ResponseData = table.Column<JsonObject>(type: "jsonb", nullable: true),
                Score = table.Column<int>(type: "integer", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_GameRecord", x => x.RecordId);
                table.ForeignKey(
                    name: "FK_GameRecord_AspNetUsers_MemberId",
                    column: x => x.MemberId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_GameRecord_EventGameInstance_InstanceId",
                    column: x => x.InstanceId,
                    principalTable: "EventGameInstance",
                    principalColumn: "InstanceId",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_GameRecord_Organizations_OrgId",
                    column: x => x.OrgId,
                    principalTable: "Organizations",
                    principalColumn: "OrgId",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AspNetRoleClaims_RoleId",
            table: "AspNetRoleClaims",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "RoleNameIndex",
            table: "AspNetRoles",
            column: "NormalizedName",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_AspNetUserClaims_UserId",
            table: "AspNetUserClaims",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_AspNetUserLogins_UserId",
            table: "AspNetUserLogins",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_AspNetUserRoles_RoleId",
            table: "AspNetUserRoles",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "EmailIndex",
            table: "AspNetUsers",
            column: "NormalizedEmail",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_Member_CreatedAt",
            table: "AspNetUsers",
            column: "CreatedAt");

        migrationBuilder.CreateIndex(
            name: "IX_Member_OrgId_Status",
            table: "AspNetUsers",
            columns: new[] { "OrgId", "Status" });

        migrationBuilder.CreateIndex(
            name: "IX_Member_Status",
            table: "AspNetUsers",
            column: "Status");

        migrationBuilder.CreateIndex(
            name: "UK_Member_Org_LocalMemberNumber",
            table: "AspNetUsers",
            columns: new[] { "OrgId", "LocalMemberNumber" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "UK_Member_Org_NormalizedUserName",
            table: "AspNetUsers",
            columns: new[] { "OrgId", "NormalizedUserName" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "UserNameIndex",
            table: "AspNetUsers",
            column: "NormalizedUserName");

        migrationBuilder.CreateIndex(
            name: "IX_Event_OrgId_Status",
            table: "Event",
            columns: new[] { "OrgId", "Status" });

        migrationBuilder.CreateIndex(
            name: "IX_Event_StartTime",
            table: "Event",
            column: "StartTime");

        migrationBuilder.CreateIndex(
            name: "IX_Event_Status",
            table: "Event",
            column: "Status");

        migrationBuilder.CreateIndex(
            name: "IX_EventContentBlock_BlockType",
            table: "EventContentBlock",
            column: "BlockType");

        migrationBuilder.CreateIndex(
            name: "IX_EventContentBlock_EventId_OrderNum",
            table: "EventContentBlock",
            columns: new[] { "EventId", "OrderNum" });

        migrationBuilder.CreateIndex(
            name: "IX_EventContentBlock_EventId_Visible",
            table: "EventContentBlock",
            columns: new[] { "EventId", "Visible" });

        migrationBuilder.CreateIndex(
            name: "IX_EventGameInstance_EventId_OrderNum",
            table: "EventGameInstance",
            columns: new[] { "EventId", "OrderNum" });

        migrationBuilder.CreateIndex(
            name: "IX_EventGameInstance_EventId_Status",
            table: "EventGameInstance",
            columns: new[] { "EventId", "Status" });

        migrationBuilder.CreateIndex(
            name: "IX_EventGameInstance_GameId",
            table: "EventGameInstance",
            column: "GameId");

        migrationBuilder.CreateIndex(
            name: "IX_EventGameInstance_Status",
            table: "EventGameInstance",
            column: "Status");

        migrationBuilder.CreateIndex(
            name: "IX_Game_CreatedAt",
            table: "Game",
            column: "CreatedAt");

        migrationBuilder.CreateIndex(
            name: "IX_Game_CreatedBy",
            table: "Game",
            column: "CreatedBy");

        migrationBuilder.CreateIndex(
            name: "IX_Game_Type",
            table: "Game",
            column: "Type");

        migrationBuilder.CreateIndex(
            name: "IX_GameRecord_CreatedAt",
            table: "GameRecord",
            column: "CreatedAt");

        migrationBuilder.CreateIndex(
            name: "IX_GameRecord_InstanceId_MemberId",
            table: "GameRecord",
            columns: new[] { "InstanceId", "MemberId" });

        migrationBuilder.CreateIndex(
            name: "IX_GameRecord_MemberId",
            table: "GameRecord",
            column: "MemberId");

        migrationBuilder.CreateIndex(
            name: "IX_GameRecord_OrgId_CreatedAt",
            table: "GameRecord",
            columns: new[] { "OrgId", "CreatedAt" });

        migrationBuilder.CreateIndex(
            name: "IX_Guest_EventId_Order",
            table: "Guest",
            columns: new[] { "EventId", "Order" });

        migrationBuilder.CreateIndex(
            name: "IX_MemberActivityLogs_MemberId",
            table: "MemberActivityLogs",
            column: "MemberId");

        migrationBuilder.CreateIndex(
            name: "IX_MemberActivityLogs_OrgId",
            table: "MemberActivityLogs",
            column: "OrgId");

        migrationBuilder.CreateIndex(
            name: "IX_Organization_OrganizationCode",
            table: "Organizations",
            column: "OrganizationCode",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_RaffleTicket_MemberId",
            table: "RaffleTickets",
            column: "MemberId");

        migrationBuilder.CreateIndex(
            name: "IX_RaffleTicket_OrgId",
            table: "RaffleTickets",
            column: "OrgId");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AspNetRoleClaims");

        migrationBuilder.DropTable(
            name: "AspNetUserClaims");

        migrationBuilder.DropTable(
            name: "AspNetUserLogins");

        migrationBuilder.DropTable(
            name: "AspNetUserRoles");

        migrationBuilder.DropTable(
            name: "AspNetUserTokens");

        migrationBuilder.DropTable(
            name: "EventContentBlock");

        migrationBuilder.DropTable(
            name: "GameRecord");

        migrationBuilder.DropTable(
            name: "Guest");

        migrationBuilder.DropTable(
            name: "MemberActivityLogs");

        migrationBuilder.DropTable(
            name: "RaffleTickets");

        migrationBuilder.DropTable(
            name: "AspNetRoles");

        migrationBuilder.DropTable(
            name: "EventGameInstance");

        migrationBuilder.DropTable(
            name: "Event");

        migrationBuilder.DropTable(
            name: "Game");

        migrationBuilder.DropTable(
            name: "AspNetUsers");

        migrationBuilder.DropTable(
            name: "Organizations");
    }
}
