using Xunit;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Common.Enums.Event;
using MeetlyOmni.Api.Common.Enums.EventContentBlock;
using MeetlyOmni.Api.Common.Enums.Game;
using MeetlyOmni.Api.Common.Enums.Members;
using MeetlyOmni.Api.Common.Enums.Organization;
using MeetlyOmni.Api.Common.Enums.RaffleTicket;
using MeetlyOmni.Api.Common.Enums.MemberActivityLog;
using System;
using System.Text.Json.Nodes;
using System.Collections.Generic;

namespace MeetlyOmni.Tests
{
    public class AllEntityTests
    {
        [Fact]
        public void EventContentBlock_CanCreateAndSetProperties()
        {
            // Arrange
            var blockId = Guid.NewGuid();
            var eventId = Guid.NewGuid();
            var blockType = BlockType.Text;
            var title = "Test Block";
            var content = new JsonObject { ["key"] = "value" };
            var orderNum = 1;
            var visible = true;

            // Act
            var block = new EventContentBlock
            {
                BlockId = blockId,
                EventId = eventId,
                BlockType = blockType,
                Title = title,
                Content = content,
                OrderNum = orderNum,
                Visible = visible
            };

            // Assert
            Assert.Equal(blockId, block.BlockId);
            Assert.Equal(eventId, block.EventId);
            Assert.Equal(blockType, block.BlockType);
            Assert.Equal(title, block.Title);
            Assert.Equal(content, block.Content);
            Assert.Equal(orderNum, block.OrderNum);
            Assert.Equal(visible, block.Visible);
        }

        [Fact]
        public void EventContentBlock_CanSetNullValues()
        {
            // Arrange & Act
            var block = new EventContentBlock
            {
                Title = null,
                Content = null,
                OrderNum = null,
                Visible = null
            };

            // Assert
            Assert.Null(block.Title);
            Assert.Null(block.Content);
            Assert.Null(block.OrderNum);
            Assert.Null(block.Visible);
        }

        [Fact]
        public void Event_CanCreateAndSetProperties()
        {
            // Arrange
            var eventId = Guid.NewGuid();
            var orgId = Guid.NewGuid();
            var title = "Test Event";
            var description = "Test Description";
            var status = EventStatus.Draft;

            // Act
            var eventEntity = new Event
            {
                EventId = eventId,
                OrgId = orgId,
                Title = title,
                Description = description,
                Status = status
            };

            // Assert
            Assert.Equal(eventId, eventEntity.EventId);
            Assert.Equal(orgId, eventEntity.OrgId);
            Assert.Equal(title, eventEntity.Title);
            Assert.Equal(description, eventEntity.Description);
            Assert.Equal(status, eventEntity.Status);
        }

        [Fact]
        public void Event_CanSetAllProperties()
        {
            // Arrange
            var eventEntity = new Event
            {
                EventId = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                Title = "Test Event",
                Description = "Test Description",
                Status = EventStatus.Draft,
                StartTime = DateTimeOffset.Now,
                EndTime = DateTimeOffset.Now.AddHours(2),
                Location = "Test Location",
                Language = "en",
                CoverImageUrl = "https://example.com/cover.jpg",
                CreatedAt = DateTimeOffset.Now,
                UpdatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, eventEntity.EventId);
            Assert.NotEqual(Guid.Empty, eventEntity.OrgId);
            Assert.Equal("Test Event", eventEntity.Title);
            Assert.Equal("Test Description", eventEntity.Description);
            Assert.Equal(EventStatus.Draft, eventEntity.Status);
            Assert.NotNull(eventEntity.StartTime);
            Assert.NotNull(eventEntity.EndTime);
            Assert.Equal("Test Location", eventEntity.Location);
            Assert.Equal("en", eventEntity.Language);
            Assert.Equal("https://example.com/cover.jpg", eventEntity.CoverImageUrl);
            Assert.NotNull(eventEntity.CreatedAt);
            Assert.NotNull(eventEntity.UpdatedAt);
        }

        [Fact]
        public void Game_CanCreateAndSetProperties()
        {
            // Arrange
            var gameId = Guid.NewGuid();
            var title = "Test Game";
            var gameType = GameType.Quiz;
            var config = new JsonObject { ["maxPlayers"] = 10 };

            // Act
            var game = new Game
            {
                GameId = gameId,
                Title = title,
                Type = gameType,
                Config = config
            };

            // Assert
            Assert.Equal(gameId, game.GameId);
            Assert.Equal(title, game.Title);
            Assert.Equal(gameType, game.Type);
            Assert.Equal(config, game.Config);
        }

        [Fact]
        public void Game_CanSetAllProperties()
        {
            // Arrange
            var game = new Game
            {
                GameId = Guid.NewGuid(),
                Title = "Test Game",
                Type = GameType.Quiz,
                Config = new JsonObject { ["maxPlayers"] = 10, ["timeLimit"] = 300 },
                CreatedBy = Guid.NewGuid(),
                CreatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, game.GameId);
            Assert.Equal("Test Game", game.Title);
            Assert.Equal(GameType.Quiz, game.Type);
            Assert.NotNull(game.Config);
            Assert.NotEqual(Guid.Empty, game.CreatedBy);
            Assert.NotNull(game.CreatedAt);
        }

        [Fact]
        public void Guest_CanCreateAndSetProperties()
        {
            // Arrange
            var guestId = Guid.NewGuid();
            var eventId = Guid.NewGuid();
            var name = "Test Guest";
            var avatarUrl = "https://example.com/avatar.jpg";
            var bio = "Test bio";

            // Act
            var guest = new Guest
            {
                GuestId = guestId,
                EventId = eventId,
                Name = name,
                AvatarUrl = avatarUrl,
                Bio = bio
            };

            // Assert
            Assert.Equal(guestId, guest.GuestId);
            Assert.Equal(eventId, guest.EventId);
            Assert.Equal(name, guest.Name);
            Assert.Equal(avatarUrl, guest.AvatarUrl);
            Assert.Equal(bio, guest.Bio);
        }

        [Fact]
        public void Guest_CanSetAllProperties()
        {
            // Arrange
            var guest = new Guest
            {
                GuestId = Guid.NewGuid(),
                EventId = Guid.NewGuid(),
                Name = "Test Guest",
                AvatarUrl = "https://example.com/avatar.jpg",
                Bio = "Test bio",
                Company = "Test Company",
                Position = "Test Position",
                SocialLinks = new JsonObject { ["linkedin"] = "https://linkedin.com/test" },
                Order = 1
            };

            // Assert
            Assert.NotEqual(Guid.Empty, guest.GuestId);
            Assert.NotEqual(Guid.Empty, guest.EventId);
            Assert.Equal("Test Guest", guest.Name);
            Assert.Equal("https://example.com/avatar.jpg", guest.AvatarUrl);
            Assert.Equal("Test bio", guest.Bio);
            Assert.Equal("Test Company", guest.Company);
            Assert.Equal("Test Position", guest.Position);
            Assert.NotNull(guest.SocialLinks);
            Assert.Equal(1, guest.Order);
        }

        [Fact]
        public void Member_CanCreateAndSetProperties()
        {
            // Arrange
            var id = Guid.NewGuid();
            var orgId = Guid.NewGuid();
            var email = "member@example.com";
            var nickname = "Test Member";
            var status = MemberStatus.Active;

            // Act
            var member = new Member
            {
                Id = id,
                OrgId = orgId,
                Email = email,
                Nickname = nickname,
                Status = status
            };

            // Assert
            Assert.Equal(id, member.Id);
            Assert.Equal(orgId, member.OrgId);
            Assert.Equal(email, member.Email);
            Assert.Equal(nickname, member.Nickname);
            Assert.Equal(status, member.Status);
        }

        [Fact]
        public void Member_CanSetAllProperties()
        {
            // Arrange
            var member = new Member
            {
                Id = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                LocalMemberNumber = 12345,
                Email = "member@example.com",
                PasswordHash = "hashedpassword",
                Nickname = "Test Member",
                Phone = "+1234567890",
                LanguagePref = "en",
                Tags = new List<string> { "vip", "early-adopter" },
                Points = 100,
                Status = MemberStatus.Active,
                LastLogin = DateTimeOffset.Now,
                CreatedAt = DateTimeOffset.Now,
                UpdatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, member.Id);
            Assert.NotEqual(Guid.Empty, member.OrgId);
            Assert.Equal(12345, member.LocalMemberNumber);
            Assert.Equal("member@example.com", member.Email);
            Assert.Equal("hashedpassword", member.PasswordHash);
            Assert.Equal("Test Member", member.Nickname);
            Assert.Equal("+1234567890", member.Phone);
            Assert.Equal("en", member.LanguagePref);
            Assert.Equal(2, member.Tags.Count);
            Assert.Equal(100, member.Points);
            Assert.Equal(MemberStatus.Active, member.Status);
            Assert.NotNull(member.LastLogin);
            Assert.NotNull(member.CreatedAt);
            Assert.NotNull(member.UpdatedAt);
        }

        [Fact]
        public void Organization_CanCreateAndSetProperties()
        {
            // Arrange
            var orgId = Guid.NewGuid();
            var organizationName = "Test Organization";
            var description = "Test Organization Description";
            var planType = PlanType.Free;

            // Act
            var organization = new Organization
            {
                OrgId = orgId,
                OrganizationName = organizationName,
                Description = description,
                PlanType = planType
            };

            // Assert
            Assert.Equal(orgId, organization.OrgId);
            Assert.Equal(organizationName, organization.OrganizationName);
            Assert.Equal(description, organization.Description);
            Assert.Equal(planType, organization.PlanType);
        }

        [Fact]
        public void Organization_CanSetAllProperties()
        {
            // Arrange
            var organization = new Organization
            {
                OrgId = Guid.NewGuid(),
                OrganizationCode = "ORG001",
                OrganizationName = "Test Organization",
                LogoUrl = "https://example.com/logo.png",
                CoverImageUrl = "https://example.com/cover.png",
                Description = "Test Organization Description",
                Location = "Test Location",
                WebsiteUrl = "https://example.com",
                IndustryTags = new List<string> { "tech", "startup" },
                FollowerCount = 1000,
                IsVerified = true,
                PlanType = PlanType.Pro,
                CreatedAt = DateTimeOffset.Now,
                UpdatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, organization.OrgId);
            Assert.Equal("ORG001", organization.OrganizationCode);
            Assert.Equal("Test Organization", organization.OrganizationName);
            Assert.Equal("https://example.com/logo.png", organization.LogoUrl);
            Assert.Equal("https://example.com/cover.png", organization.CoverImageUrl);
            Assert.Equal("Test Organization Description", organization.Description);
            Assert.Equal("Test Location", organization.Location);
            Assert.Equal("https://example.com", organization.WebsiteUrl);
            Assert.Equal(2, organization.IndustryTags.Count);
            Assert.Equal(1000, organization.FollowerCount);
            Assert.True(organization.IsVerified);
            Assert.Equal(PlanType.Pro, organization.PlanType);
            Assert.NotNull(organization.CreatedAt);
            Assert.NotNull(organization.UpdatedAt);
        }

        [Fact]
        public void RaffleTicket_CanCreateAndSetProperties()
        {
            // Arrange
            var ticketId = Guid.NewGuid();
            var orgId = Guid.NewGuid();
            var memberId = Guid.NewGuid();
            var status = RaffleTicketStatus.Unused;
            var issuedBy = RaffleIssuedSource.Signup;

            // Act
            var ticket = new RaffleTicket
            {
                TicketId = ticketId,
                OrgId = orgId,
                MemberId = memberId,
                Status = status,
                IssuedBy = issuedBy
            };

            // Assert
            Assert.Equal(ticketId, ticket.TicketId);
            Assert.Equal(orgId, ticket.OrgId);
            Assert.Equal(memberId, ticket.MemberId);
            Assert.Equal(status, ticket.Status);
            Assert.Equal(issuedBy, ticket.IssuedBy);
        }

        [Fact]
        public void RaffleTicket_CanSetAllProperties()
        {
            // Arrange
            var ticket = new RaffleTicket
            {
                TicketId = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                MemberId = Guid.NewGuid(),
                IssuedBy = RaffleIssuedSource.Signup,
                Status = RaffleTicketStatus.Unused,
                IssueTime = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, ticket.TicketId);
            Assert.NotEqual(Guid.Empty, ticket.OrgId);
            Assert.NotEqual(Guid.Empty, ticket.MemberId);
            Assert.Equal(RaffleIssuedSource.Signup, ticket.IssuedBy);
            Assert.Equal(RaffleTicketStatus.Unused, ticket.Status);
            Assert.NotNull(ticket.IssueTime);
        }

        [Fact]
        public void GameRecord_CanCreateAndSetProperties()
        {
            // Arrange
            var recordId = Guid.NewGuid();
            var instanceId = Guid.NewGuid();
            var memberId = Guid.NewGuid();
            var orgId = Guid.NewGuid();
            var score = 100;
            var responseData = new JsonObject { ["answer"] = "correct" };

            // Act
            var record = new GameRecord
            {
                RecordId = recordId,
                InstanceId = instanceId,
                MemberId = memberId,
                OrgId = orgId,
                Score = score,
                ResponseData = responseData
            };

            // Assert
            Assert.Equal(recordId, record.RecordId);
            Assert.Equal(instanceId, record.InstanceId);
            Assert.Equal(memberId, record.MemberId);
            Assert.Equal(orgId, record.OrgId);
            Assert.Equal(score, record.Score);
            Assert.Equal(responseData, record.ResponseData);
        }

        [Fact]
        public void GameRecord_CanSetAllProperties()
        {
            // Arrange
            var record = new GameRecord
            {
                RecordId = Guid.NewGuid(),
                InstanceId = Guid.NewGuid(),
                MemberId = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                ResponseData = new JsonObject { ["answer"] = "correct", ["time"] = 120 },
                Score = 100,
                CreatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, record.RecordId);
            Assert.NotEqual(Guid.Empty, record.InstanceId);
            Assert.NotEqual(Guid.Empty, record.MemberId);
            Assert.NotEqual(Guid.Empty, record.OrgId);
            Assert.NotNull(record.ResponseData);
            Assert.Equal(100, record.Score);
            Assert.NotNull(record.CreatedAt);
        }

        [Fact]
        public void EventGameInstance_CanCreateAndSetProperties()
        {
            // Arrange
            var instanceId = Guid.NewGuid();
            var eventId = Guid.NewGuid();
            var gameId = Guid.NewGuid();
            var status = MeetlyOmni.Api.Common.Enums.EventGameInstance.InstanceStatus.Active;

            // Act
            var instance = new EventGameInstance
            {
                InstanceId = instanceId,
                EventId = eventId,
                GameId = gameId,
                Status = status
            };

            // Assert
            Assert.Equal(instanceId, instance.InstanceId);
            Assert.Equal(eventId, instance.EventId);
            Assert.Equal(gameId, instance.GameId);
            Assert.Equal(status, instance.Status);
        }



        [Fact]
        public void EventGameInstance_CanSetAllProperties()
        {
            // Arrange
            var instance = new EventGameInstance
            {
                InstanceId = Guid.NewGuid(),
                EventId = Guid.NewGuid(),
                GameId = Guid.NewGuid(),
                TitleOverride = "Custom Game Title",
                Status = MeetlyOmni.Api.Common.Enums.EventGameInstance.InstanceStatus.Active,
                OrderNum = 1,
                StartTime = DateTimeOffset.Now,
                EndTime = DateTimeOffset.Now.AddHours(1)
            };

            // Assert
            Assert.NotEqual(Guid.Empty, instance.InstanceId);
            Assert.NotEqual(Guid.Empty, instance.EventId);
            Assert.NotEqual(Guid.Empty, instance.GameId);
            Assert.Equal("Custom Game Title", instance.TitleOverride);
            Assert.Equal(MeetlyOmni.Api.Common.Enums.EventGameInstance.InstanceStatus.Active, instance.Status);
            Assert.Equal(1, instance.OrderNum);
            Assert.NotNull(instance.StartTime);
            Assert.NotNull(instance.EndTime);
        }

        [Fact]
        public void MemberActivityLog_CanCreateAndSetProperties()
        {
            // Arrange
            var logId = Guid.NewGuid();
            var memberId = Guid.NewGuid();
            var orgId = Guid.NewGuid();
            var eventType = MemberEventType.SignIn;
            var eventDetail = new JsonObject { ["ip"] = "192.168.1.1" };

            // Act
            var log = new MemberActivityLog
            {
                LogId = logId,
                MemberId = memberId,
                OrgId = orgId,
                EventType = eventType,
                EventDetail = eventDetail
            };

            // Assert
            Assert.Equal(logId, log.LogId);
            Assert.Equal(memberId, log.MemberId);
            Assert.Equal(orgId, log.OrgId);
            Assert.Equal(eventType, log.EventType);
            Assert.Equal(eventDetail, log.EventDetail);
        }

        [Fact]
        public void MemberActivityLog_CanSetAllProperties()
        {
            // Arrange
            var log = new MemberActivityLog
            {
                LogId = Guid.NewGuid(),
                MemberId = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                EventType = MemberEventType.SignIn,
                EventDetail = new JsonObject { ["ip"] = "192.168.1.1", ["userAgent"] = "Mozilla/5.0" },
                CreatedAt = DateTimeOffset.Now
            };

            // Assert
            Assert.NotEqual(Guid.Empty, log.LogId);
            Assert.NotEqual(Guid.Empty, log.MemberId);
            Assert.NotEqual(Guid.Empty, log.OrgId);
            Assert.Equal(MemberEventType.SignIn, log.EventType);
            Assert.NotNull(log.EventDetail);
            Assert.NotNull(log.CreatedAt);
        }

        [Fact]
        public void AllEntities_DefaultValues_AreCorrect()
        {
            // Test default values for all entities
            var block = new EventContentBlock();
            var eventEntity = new Event();
            var game = new Game();
            var guest = new Guest();
            var member = new Member();
            var organization = new Organization();
            var ticket = new RaffleTicket();
            var record = new GameRecord();
            var instance = new EventGameInstance();
            var log = new MemberActivityLog();

            // Assert all have correct default values
            Assert.Equal(Guid.Empty, block.BlockId);
            Assert.Equal(Guid.Empty, eventEntity.EventId);
            Assert.Equal(Guid.Empty, game.GameId);
            Assert.Equal(Guid.Empty, guest.GuestId);
            Assert.NotEqual(Guid.Empty, member.Id); // Member.Id has default value
            Assert.Equal(Guid.Empty, organization.OrgId);
            Assert.Equal(Guid.Empty, ticket.TicketId);
            Assert.Equal(Guid.Empty, record.RecordId);
            Assert.Equal(Guid.Empty, instance.InstanceId);
            Assert.Equal(Guid.Empty, log.LogId);
        }

        [Fact]
        public void AllEntities_CanBeCreatedWithMinimalData()
        {
            // Test that all entities can be created with minimal required data
            var block = new EventContentBlock { BlockId = Guid.NewGuid() };
            var eventEntity = new Event { EventId = Guid.NewGuid() };
            var game = new Game { GameId = Guid.NewGuid() };
            var guest = new Guest { GuestId = Guid.NewGuid() };
            var member = new Member { Id = Guid.NewGuid() };
            var organization = new Organization { OrgId = Guid.NewGuid() };
            var ticket = new RaffleTicket { TicketId = Guid.NewGuid() };
            var record = new GameRecord { RecordId = Guid.NewGuid() };
            var instance = new EventGameInstance { InstanceId = Guid.NewGuid() };
            var log = new MemberActivityLog { LogId = Guid.NewGuid() };

            // Assert all can be created
            Assert.NotNull(block);
            Assert.NotNull(eventEntity);
            Assert.NotNull(game);
            Assert.NotNull(guest);
            Assert.NotNull(member);
            Assert.NotNull(organization);
            Assert.NotNull(ticket);
            Assert.NotNull(record);
            Assert.NotNull(instance);
            Assert.NotNull(log);
        }
    }
} 