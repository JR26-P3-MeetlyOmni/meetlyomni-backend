// <copyright file="20250723041643_MemberUuidMigrationFixed.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

#nullable disable

namespace MeetlyOmni.Api.Migrations
{
    using System;

    using Microsoft.EntityFrameworkCore.Migrations;

    /// <inheritdoc />
    public partial class MemberUuidMigrationFixed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // ⚠️ WARNING: This migration changes primary key types and will affect existing data
            // For production environments, ensure proper data backup and migration strategy

            // Drop foreign key constraints first
            migrationBuilder.DropForeignKey(
                name: "FK_GameRecord_Members_MemberId",
                table: "GameRecord");

            migrationBuilder.DropForeignKey(
                name: "FK_MemberActivityLogs_Members_MemberId",
                table: "MemberActivityLogs");

            migrationBuilder.DropForeignKey(
                name: "FK_RaffleTickets_Members_MemberId",
                table: "RaffleTickets");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Members",
                table: "Members");

            // Create a temporary mapping table to preserve member relationships
            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS member_id_mapping (
                    old_member_id VARCHAR(50) PRIMARY KEY,
                    new_member_id UUID DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL,
                    local_member_number INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            ");

            // Populate mapping table with existing member data (if any exists)
            migrationBuilder.Sql(@"
                INSERT INTO member_id_mapping (old_member_id, org_id, local_member_number)
                SELECT ""MemberId"", ""OrgId"", ""LocalMemberNumber""
                FROM ""Members""
                ON CONFLICT (old_member_id) DO NOTHING;
            ");

            // Drop the old string MemberId column
            migrationBuilder.DropColumn(
                name: "MemberId",
                table: "Members");

            // Rename indexes to match new naming convention
            migrationBuilder.RenameIndex(
                name: "IX_Member_OrgId_LocalMemberNumber",
                table: "Members",
                newName: "UK_Member_Org_LocalNumber");

            migrationBuilder.RenameIndex(
                name: "IX_Member_OrgId_Email",
                table: "Members",
                newName: "UK_Member_Org_Email");

            // Add new UUID primary key to Members
            migrationBuilder.AddColumn<Guid>(
                name: "Id",
                table: "Members",
                type: "uuid",
                nullable: false,
                defaultValueSql: "gen_random_uuid()");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Members",
                table: "Members",
                column: "Id");

            // Update Members table with mapped UUIDs where possible
            migrationBuilder.Sql(@"
                UPDATE ""Members"" 
                SET ""Id"" = (
                    SELECT new_member_id 
                    FROM member_id_mapping 
                    WHERE member_id_mapping.org_id = ""Members"".""OrgId"" 
                    AND member_id_mapping.local_member_number = ""Members"".""LocalMemberNumber""
                    LIMIT 1
                )
                WHERE EXISTS (
                    SELECT 1 FROM member_id_mapping 
                    WHERE member_id_mapping.org_id = ""Members"".""OrgId"" 
                    AND member_id_mapping.local_member_number = ""Members"".""LocalMemberNumber""
                );
            ");

            // Convert foreign key columns to UUID type using mapping where possible
            migrationBuilder.Sql(@"
                -- Update RaffleTickets
                ALTER TABLE ""RaffleTickets"" ADD COLUMN ""NewMemberId"" UUID;
                
                UPDATE ""RaffleTickets"" 
                SET ""NewMemberId"" = m.new_member_id
                FROM member_id_mapping m
                WHERE ""RaffleTickets"".""MemberId"" = m.old_member_id;
                
                ALTER TABLE ""RaffleTickets"" DROP COLUMN ""MemberId"";
                ALTER TABLE ""RaffleTickets"" RENAME COLUMN ""NewMemberId"" TO ""MemberId"";
                ALTER TABLE ""RaffleTickets"" ALTER COLUMN ""MemberId"" SET NOT NULL;
            ");

            migrationBuilder.Sql(@"
                -- Update MemberActivityLogs
                ALTER TABLE ""MemberActivityLogs"" ADD COLUMN ""NewMemberId"" UUID;
                
                UPDATE ""MemberActivityLogs"" 
                SET ""NewMemberId"" = m.new_member_id
                FROM member_id_mapping m
                WHERE ""MemberActivityLogs"".""MemberId"" = m.old_member_id;
                
                ALTER TABLE ""MemberActivityLogs"" DROP COLUMN ""MemberId"";
                ALTER TABLE ""MemberActivityLogs"" RENAME COLUMN ""NewMemberId"" TO ""MemberId"";
                ALTER TABLE ""MemberActivityLogs"" ALTER COLUMN ""MemberId"" SET NOT NULL;
            ");

            migrationBuilder.Sql(@"
                -- Update GameRecord
                ALTER TABLE ""GameRecord"" ADD COLUMN ""NewMemberId"" UUID;
                
                UPDATE ""GameRecord"" 
                SET ""NewMemberId"" = m.new_member_id
                FROM member_id_mapping m
                WHERE ""GameRecord"".""MemberId"" = m.old_member_id;
                
                ALTER TABLE ""GameRecord"" DROP COLUMN ""MemberId"";
                ALTER TABLE ""GameRecord"" RENAME COLUMN ""NewMemberId"" TO ""MemberId"";
                ALTER TABLE ""GameRecord"" ALTER COLUMN ""MemberId"" SET NOT NULL;
            ");

            // Clean up mapping table (optional - keep for debugging)
            // migrationBuilder.Sql("DROP TABLE IF EXISTS member_id_mapping;");

            // Recreate foreign key relationships
            migrationBuilder.AddForeignKey(
                name: "FK_Game_Members_CreatedBy",
                table: "Game",
                column: "CreatedBy",
                principalTable: "Members",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_GameRecord_Members_MemberId",
                table: "GameRecord",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_MemberActivityLogs_Members_MemberId",
                table: "MemberActivityLogs",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RaffleTickets_Members_MemberId",
                table: "RaffleTickets",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // ⚠️ WARNING: Rollback will result in data loss as UUID to string conversion is not reversible

            // Drop foreign key constraints
            migrationBuilder.DropForeignKey(
                name: "FK_Game_Members_CreatedBy",
                table: "Game");

            migrationBuilder.DropForeignKey(
                name: "FK_GameRecord_Members_MemberId",
                table: "GameRecord");

            migrationBuilder.DropForeignKey(
                name: "FK_MemberActivityLogs_Members_MemberId",
                table: "MemberActivityLogs");

            migrationBuilder.DropForeignKey(
                name: "FK_RaffleTickets_Members_MemberId",
                table: "RaffleTickets");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Members",
                table: "Members");

            // Drop the UUID column
            migrationBuilder.DropColumn(
                name: "Id",
                table: "Members");

            // Rename indexes back
            migrationBuilder.RenameIndex(
                name: "UK_Member_Org_LocalNumber",
                table: "Members",
                newName: "IX_Member_OrgId_LocalMemberNumber");

            migrationBuilder.RenameIndex(
                name: "UK_Member_Org_Email",
                table: "Members",
                newName: "IX_Member_OrgId_Email");

            // Restore string columns - this will result in data loss
            migrationBuilder.AddColumn<string>(
                name: "MemberId",
                table: "Members",
                type: "character varying(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: string.Empty);

            // Convert foreign key columns back to string - this will result in data loss
            migrationBuilder.Sql(@"
                ALTER TABLE ""RaffleTickets"" ALTER COLUMN ""MemberId"" TYPE character varying(50) USING ''::character varying(50);
                ALTER TABLE ""MemberActivityLogs"" ALTER COLUMN ""MemberId"" TYPE character varying(50) USING ''::character varying(50);
                ALTER TABLE ""GameRecord"" ALTER COLUMN ""MemberId"" TYPE character varying(50) USING ''::character varying(50);
            ");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Members",
                table: "Members",
                column: "MemberId");

            // Clean up mapping table
            migrationBuilder.Sql("DROP TABLE IF EXISTS member_id_mapping;");

            // Recreate old foreign key relationships
            migrationBuilder.AddForeignKey(
                name: "FK_GameRecord_Members_MemberId",
                table: "GameRecord",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "MemberId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_MemberActivityLogs_Members_MemberId",
                table: "MemberActivityLogs",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "MemberId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RaffleTickets_Members_MemberId",
                table: "RaffleTickets",
                column: "MemberId",
                principalTable: "Members",
                principalColumn: "MemberId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
