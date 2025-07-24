// <copyright file="20250722072819_AddMissingConstraintsAndIndexes.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

#nullable disable

namespace MeetlyOmni.Api.Migrations
{
    using System;

    using Microsoft.EntityFrameworkCore.Migrations;

    /// <inheritdoc />
    public partial class AddMissingConstraintsAndIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Event_Organizations_OrganizationOrgId",
                table: "Event");

            migrationBuilder.DropIndex(
                name: "IX_Members_OrgId",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Guest_EventId",
                table: "Guest");

            migrationBuilder.DropIndex(
                name: "IX_GameRecord_InstanceId",
                table: "GameRecord");

            migrationBuilder.DropIndex(
                name: "IX_GameRecord_OrgId",
                table: "GameRecord");

            migrationBuilder.DropIndex(
                name: "IX_EventGameInstance_EventId",
                table: "EventGameInstance");

            migrationBuilder.DropIndex(
                name: "IX_EventContentBlock_EventId",
                table: "EventContentBlock");

            migrationBuilder.DropIndex(
                name: "IX_Event_OrganizationOrgId",
                table: "Event");

            migrationBuilder.DropColumn(
                name: "OrganizationOrgId",
                table: "Event");

            migrationBuilder.AlterColumn<int>(
                name: "Order",
                table: "Guest",
                type: "integer",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "integer");

            migrationBuilder.AlterColumn<bool>(
                name: "Visible",
                table: "EventContentBlock",
                type: "boolean",
                nullable: true,
                defaultValue: true,
                oldClrType: typeof(bool),
                oldType: "boolean",
                oldNullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "OrderNum",
                table: "EventContentBlock",
                type: "integer",
                nullable: true,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "integer",
                oldNullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "Event",
                type: "timestamp with time zone",
                nullable: false,
                defaultValueSql: "NOW()");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "UpdatedAt",
                table: "Event",
                type: "timestamp with time zone",
                nullable: false,
                defaultValueSql: "NOW()");

            migrationBuilder.CreateIndex(
                name: "IX_Organization_OrganizationCode",
                table: "Organizations",
                column: "OrganizationCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Member_CreatedAt",
                table: "Members",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Member_OrgId_Email",
                table: "Members",
                columns: new[] { "OrgId", "Email" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Member_OrgId_LocalMemberNumber",
                table: "Members",
                columns: new[] { "OrgId", "LocalMemberNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Member_OrgId_Status",
                table: "Members",
                columns: new[] { "OrgId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_Member_Status",
                table: "Members",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_Guest_EventId_Order",
                table: "Guest",
                columns: new[] { "EventId", "Order" });

            migrationBuilder.CreateIndex(
                name: "IX_GameRecord_CreatedAt",
                table: "GameRecord",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_GameRecord_InstanceId_MemberId",
                table: "GameRecord",
                columns: new[] { "InstanceId", "MemberId" });

            migrationBuilder.CreateIndex(
                name: "IX_GameRecord_OrgId_CreatedAt",
                table: "GameRecord",
                columns: new[] { "OrgId", "CreatedAt" });

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
                name: "IX_EventGameInstance_EventId_OrderNum",
                table: "EventGameInstance",
                columns: new[] { "EventId", "OrderNum" });

            migrationBuilder.CreateIndex(
                name: "IX_EventGameInstance_EventId_Status",
                table: "EventGameInstance",
                columns: new[] { "EventId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_EventGameInstance_Status",
                table: "EventGameInstance",
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

            migrationBuilder.AddForeignKey(
                name: "FK_Event_Organizations_OrgId",
                table: "Event",
                column: "OrgId",
                principalTable: "Organizations",
                principalColumn: "OrgId",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Event_Organizations_OrgId",
                table: "Event");

            migrationBuilder.DropIndex(
                name: "IX_Organization_OrganizationCode",
                table: "Organizations");

            migrationBuilder.DropIndex(
                name: "IX_Member_CreatedAt",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Member_OrgId_Email",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Member_OrgId_LocalMemberNumber",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Member_OrgId_Status",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Member_Status",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Guest_EventId_Order",
                table: "Guest");

            migrationBuilder.DropIndex(
                name: "IX_GameRecord_CreatedAt",
                table: "GameRecord");

            migrationBuilder.DropIndex(
                name: "IX_GameRecord_InstanceId_MemberId",
                table: "GameRecord");

            migrationBuilder.DropIndex(
                name: "IX_GameRecord_OrgId_CreatedAt",
                table: "GameRecord");

            migrationBuilder.DropIndex(
                name: "IX_Game_CreatedAt",
                table: "Game");

            migrationBuilder.DropIndex(
                name: "IX_Game_CreatedBy",
                table: "Game");

            migrationBuilder.DropIndex(
                name: "IX_Game_Type",
                table: "Game");

            migrationBuilder.DropIndex(
                name: "IX_EventGameInstance_EventId_OrderNum",
                table: "EventGameInstance");

            migrationBuilder.DropIndex(
                name: "IX_EventGameInstance_EventId_Status",
                table: "EventGameInstance");

            migrationBuilder.DropIndex(
                name: "IX_EventGameInstance_Status",
                table: "EventGameInstance");

            migrationBuilder.DropIndex(
                name: "IX_EventContentBlock_BlockType",
                table: "EventContentBlock");

            migrationBuilder.DropIndex(
                name: "IX_EventContentBlock_EventId_OrderNum",
                table: "EventContentBlock");

            migrationBuilder.DropIndex(
                name: "IX_EventContentBlock_EventId_Visible",
                table: "EventContentBlock");

            migrationBuilder.DropIndex(
                name: "IX_Event_OrgId_Status",
                table: "Event");

            migrationBuilder.DropIndex(
                name: "IX_Event_StartTime",
                table: "Event");

            migrationBuilder.DropIndex(
                name: "IX_Event_Status",
                table: "Event");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "Event");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "Event");

            migrationBuilder.AlterColumn<int>(
                name: "Order",
                table: "Guest",
                type: "integer",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "integer",
                oldDefaultValue: 0);

            migrationBuilder.AlterColumn<bool>(
                name: "Visible",
                table: "EventContentBlock",
                type: "boolean",
                nullable: true,
                oldClrType: typeof(bool),
                oldType: "boolean",
                oldNullable: true,
                oldDefaultValue: true);

            migrationBuilder.AlterColumn<int>(
                name: "OrderNum",
                table: "EventContentBlock",
                type: "integer",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "integer",
                oldNullable: true,
                oldDefaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "OrganizationOrgId",
                table: "Event",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Members_OrgId",
                table: "Members",
                column: "OrgId");

            migrationBuilder.CreateIndex(
                name: "IX_Guest_EventId",
                table: "Guest",
                column: "EventId");

            migrationBuilder.CreateIndex(
                name: "IX_GameRecord_InstanceId",
                table: "GameRecord",
                column: "InstanceId");

            migrationBuilder.CreateIndex(
                name: "IX_GameRecord_OrgId",
                table: "GameRecord",
                column: "OrgId");

            migrationBuilder.CreateIndex(
                name: "IX_EventGameInstance_EventId",
                table: "EventGameInstance",
                column: "EventId");

            migrationBuilder.CreateIndex(
                name: "IX_EventContentBlock_EventId",
                table: "EventContentBlock",
                column: "EventId");

            migrationBuilder.CreateIndex(
                name: "IX_Event_OrganizationOrgId",
                table: "Event",
                column: "OrganizationOrgId");

            migrationBuilder.AddForeignKey(
                name: "FK_Event_Organizations_OrganizationOrgId",
                table: "Event",
                column: "OrganizationOrgId",
                principalTable: "Organizations",
                principalColumn: "OrgId");
        }
    }
}
