// <copyright file="SignUpService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Cryptography;

using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Organization;
using MeetlyOmni.Api.Models.Members;

using Microsoft.AspNetCore.Identity;

namespace MeetlyOmni.Api.Service.SignUpService;

public class SignUpService : ISignUpService
{
    /// <summary>
    /// The user manager.
    /// </summary>
    private readonly UserManager<Member> userManager;

    /// <summary>
    /// The role manager.
    /// </summary>
    private readonly RoleManager<ApplicationRole> roleManager;

    /// <summary>
    /// The organization repository.
    /// </summary>
    private readonly IOrganizationRepository organizationRepository;

    /// <summary>
    /// The database context.
    /// </summary>
    private readonly ApplicationDbContext dbContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="SignUpService"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="roleManager">The role manager.</param>
    /// <param name="organizationRepository">The organization repository.</param>
    /// <param name="dbContext">The database context.</param>
    public SignUpService(
        UserManager<Member> userManager,
        RoleManager<ApplicationRole> roleManager,
        IOrganizationRepository organizationRepository,
        ApplicationDbContext dbContext)
    {
        this.userManager = userManager;
        this.roleManager = roleManager;
        this.organizationRepository = organizationRepository;
        this.dbContext = dbContext;
    }

    /// <summary>
    /// Exception thrown when a signup email already exists.
    /// </summary>
    public class EmailAlreadyExistsException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EmailAlreadyExistsException"/> class.
        /// </summary>
        /// <param name="message">The exception message.</param>
        public EmailAlreadyExistsException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// Generates a unique organization code based on the name.
    /// </summary>
    /// <param name="name">Organization name.</param>
    /// <returns>Unique organization code.</returns>
    private async Task<string> GenerateUniqueOrgCodeAsync(string name)
    {
        string BaseSlug(string s) =>
            new string(s.Trim().ToLowerInvariant().Where(ch => char.IsLetterOrDigit(ch) || ch == ' ').ToArray())
            .Replace(' ', '-');

        var baseSlug = BaseSlug(name);
        for (int i = 0; i < 5; i++)
        {
            var suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            var code = $"{baseSlug}-{suffix}";
            if (!await this.organizationRepository.OrganizationCodeExistsAsync(code))
            {
                return code;
            }
        }

        return $"{baseSlug}-{Guid.NewGuid():N}";
    }

    /// <summary>
    /// Signs up a new admin member and organization, using a transaction for all-or-nothing commit.
    /// </summary>
    /// <param name="input">Signup binding model.</param>
    /// <returns>Member DTO for the created admin.</returns>
    public async Task<MemberDto> SignUpAdminAsync(SignUpBindingModel input)
    {
        // Use transaction to ensure all-or-nothing
        using var transaction = await this.dbContext.Database.BeginTransactionAsync();
        try
        {
            // Check if email already exists
            var existingMember = await this.userManager.FindByEmailAsync(input.Email);
            if (existingMember != null)
            {
                throw new EmailAlreadyExistsException($"Email '{input.Email}' already exists.");
            }

            var memberEntity = new Member
            {
                Id = Guid.NewGuid(),
                OrgId = Guid.NewGuid(),
                Email = input.Email,
                UserName = input.UserName,
                PhoneNumber = input.PhoneNumber,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };

            await this.organizationRepository.AddOrganizationAsync(new Organization
            {
                OrgId = memberEntity.OrgId,
                OrganizationCode = await this.GenerateUniqueOrgCodeAsync(input.OrganizationName),
                OrganizationName = input.OrganizationName,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });

            var createResult = await this.userManager.CreateAsync(memberEntity, input.Password);

            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException(string.Join("; ", createResult.Errors.Select(e => $"{e.Code}:{e.Description}")));
            }
            else
            {
                var roleName = "Admin";

                if (!await this.roleManager.RoleExistsAsync(roleName))
                {
                    await this.roleManager.CreateAsync(new ApplicationRole(roleName));
                }

                var addToRoleResult = await this.userManager.AddToRoleAsync(memberEntity, roleName);
            }

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
}
