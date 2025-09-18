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
    private const int _baseSlugMaxLength = 22;
    private const int _maxAttempts = 10;
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

                if (!roleCreatedResult.Succeeded)
                {
                    await transaction.RollbackAsync();
                    var errorMessages = string.Join("; ", roleCreatedResult.Errors.Select(e => e.Description));
                    _logger.LogError("Role creation failed for role {RoleName}: {Errors}", roleName, errorMessages);
                    throw new InvalidOperationException($"Role creation failed: {errorMessages}");
                }
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
        // Create base slug from organization name
        var baseSlug = new string(name.ToLowerInvariant()
            .Where(c => char.IsLetterOrDigit(c) || c == ' ')
            .ToArray())
            .Replace(' ', '-');

        // Truncate to max 22 chars to leave room for 8-char suffix (22 + 1 + 7 = 30)
        if (baseSlug.Length > _baseSlugMaxLength)
        {
            baseSlug = baseSlug.Substring(0, _baseSlugMaxLength);
        }

        // Try up to 10 times to find unique code
        for (int i = 0; i < _maxAttempts; i++)
        {
            var suffix = Guid.NewGuid().ToString("N")[..7]; // 7 random chars
            var orgCode = $"{baseSlug}-{suffix}";

            if (!await _organizationRepository.OrganizationCodeExistsAsync(orgCode))
                return orgCode;
        }

        // Fallback: use timestamp suffix (should be very rare)
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss")[..7];
        return $"{baseSlug}-{timestamp}";
    }
}
