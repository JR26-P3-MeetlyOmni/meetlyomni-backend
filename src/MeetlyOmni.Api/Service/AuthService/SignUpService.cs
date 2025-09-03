// <copyright file="SignUpService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;

using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Models.Member;
using MeetlyOmni.Api.Service.AuthService.Interfaces;

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Service.AuthService;

public class SignUpService : ISignUpService
{
    private readonly UserManager<Member> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly IOrganizationRepository _organizationRepository;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<SignUpService> _logger;

    public SignUpService(
        UserManager<Member> userManager,
        RoleManager<ApplicationRole> roleManager,
        IOrganizationRepository organizationRepository,
        ApplicationDbContext dbContext,
        ILogger<SignUpService> logger)
    {
        this._userManager = userManager;
        this._roleManager = roleManager;
        this._organizationRepository = organizationRepository;
        this._dbContext = dbContext;
        this._logger = logger;
    }

    public async Task<MemberDto> SignUpAdminAsync(AdminSignupRequest request)
    {
        using var transaction = await this._dbContext.Database.BeginTransactionAsync();
        try
        {
            var existingMember = await this._userManager.FindByEmailAsync(request.Email);
            if (existingMember != null)
            {
                throw new ConflictAppException($"Email '{request.Email}' already exists.");
            }

            var memberEntity = new Member
            {
                Id = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                Email = request.Email,
                UserName = request.UserName,
                PhoneNumber = request.PhoneNumber,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };

            await this._organizationRepository.AddOrganizationAsync(new Organization
            {
                OrgId = memberEntity.OrgId,
                OrganizationCode = await this.GenerateUniqueOrgCodeAsync(request.OrganizationName),
                OrganizationName = request.OrganizationName,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });

            var createResult = await this._userManager.CreateAsync(memberEntity, request.Password);

            if (!createResult.Succeeded)
            {
                await transaction.RollbackAsync();
                var errorMessages = string.Join("; ", createResult.Errors.Select(e => e.Description));
                _logger.LogError("User creation failed for email {Email}: {Errors}", request.Email, errorMessages);
                throw new InvalidOperationException($"User creation failed: {errorMessages}");
            }

            var roleName = "Admin";
            if (!await this._roleManager.RoleExistsAsync(roleName))
            {
                var roleCreatedResult = await this._roleManager.CreateAsync(new ApplicationRole(roleName));
            }

            var addToRoleResult = await this._userManager.AddToRoleAsync(memberEntity, roleName);

            if (!addToRoleResult.Succeeded)
            {
                await transaction.RollbackAsync();
                var errorMessages = string.Join("; ", addToRoleResult.Errors.Select(e => e.Description));
                _logger.LogError("Role assignment failed for user {Email}: {Errors}", request.Email, errorMessages);
                throw new InvalidOperationException($"Role assignment failed: {errorMessages}");
            }

            await this._dbContext.SaveChangesAsync();
            await transaction.CommitAsync();

            var dto = new MemberDto
            {
                Id = memberEntity.Id,
                Email = memberEntity.Email,
            };
            return dto;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public async Task<string> GenerateUniqueOrgCodeAsync(string name)
    {
        string BaseSlug(string s) =>
            new string(s.Trim().ToLowerInvariant().Where(ch => char.IsLetterOrDigit(ch) || ch == ' ').ToArray())
            .Replace(' ', '-');

        var baseSlug = string.IsNullOrWhiteSpace(name) ? "org" : BaseSlug(name);

        for (int i = 0; i < 5; i++)
        {
            var suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            var code = $"{baseSlug}-{suffix}";
            if (!await this._organizationRepository.OrganizationCodeExistsAsync(code))
            {
                return code;
            }
        }

        return $"{baseSlug}-{Guid.NewGuid():N}";
    }
}
