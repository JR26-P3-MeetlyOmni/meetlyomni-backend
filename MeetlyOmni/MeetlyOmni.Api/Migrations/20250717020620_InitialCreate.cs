using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MeetlyOmni.Api.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Organizations",
                columns: table => new
                {
                    OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                    OrganizationCode = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    OrganizationName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    LogoUrl = table.Column<string>(type: "text", nullable: true),
                    CoverImageUrl = table.Column<string>(type: "text", nullable: true),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Location = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    WebsiteUrl = table.Column<string>(type: "text", nullable: true),
                    IndustryTags = table.Column<List<string>>(type: "jsonb", nullable: true),
                    FollowerCount = table.Column<int>(type: "integer", nullable: false),
                    IsVerified = table.Column<bool>(type: "boolean", nullable: false),
                    PlanType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Free"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Organizations", x => x.OrgId);
                });

            migrationBuilder.CreateTable(
                name: "Members",
                columns: table => new
                {
                    MemberId = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                    LocalMemberNumber = table.Column<int>(type: "integer", nullable: false),
                    Email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    PasswordHash = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Nickname = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Phone = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    LanguagePref = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    Tags = table.Column<List<string>>(type: "jsonb", nullable: false, defaultValueSql: "'[]'::jsonb"),
                    Points = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "Active"),
                    LastLogin = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Members", x => x.MemberId);
                    table.ForeignKey(
                        name: "FK_Members_Organizations_OrgId",
                        column: x => x.OrgId,
                        principalTable: "Organizations",
                        principalColumn: "OrgId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MemberActivityLogs",
                columns: table => new
                {
                    LogId = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberId = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    OrgId = table.Column<Guid>(type: "uuid", nullable: false),
                    EventType = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false),
                    EventDetail = table.Column<string>(type: "jsonb", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MemberActivityLogs", x => x.LogId);
                    table.ForeignKey(
                        name: "FK_MemberActivityLogs_Members_MemberId",
                        column: x => x.MemberId,
                        principalTable: "Members",
                        principalColumn: "MemberId",
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
                    MemberId = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    IssuedBy = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    Status = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false),
                    IssueTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RaffleTickets", x => x.TicketId);
                    table.ForeignKey(
                        name: "FK_RaffleTickets_Members_MemberId",
                        column: x => x.MemberId,
                        principalTable: "Members",
                        principalColumn: "MemberId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RaffleTickets_Organizations_OrgId",
                        column: x => x.OrgId,
                        principalTable: "Organizations",
                        principalColumn: "OrgId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MemberActivityLogs_MemberId",
                table: "MemberActivityLogs",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_MemberActivityLogs_OrgId",
                table: "MemberActivityLogs",
                column: "OrgId");

            migrationBuilder.CreateIndex(
                name: "IX_Members_OrgId",
                table: "Members",
                column: "OrgId");

            migrationBuilder.CreateIndex(
                name: "IX_RaffleTickets_MemberId",
                table: "RaffleTickets",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_RaffleTickets_OrgId",
                table: "RaffleTickets",
                column: "OrgId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MemberActivityLogs");

            migrationBuilder.DropTable(
                name: "RaffleTickets");

            migrationBuilder.DropTable(
                name: "Members");

            migrationBuilder.DropTable(
                name: "Organizations");
        }
    }
}
