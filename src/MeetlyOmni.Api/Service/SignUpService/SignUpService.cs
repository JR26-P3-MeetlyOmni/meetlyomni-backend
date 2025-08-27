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
    private readonly UserManager<Member> _userManager;

    private readonly RoleManager<ApplicationRole> _roleManager;

    private readonly IOrganizationRepository _organizationRepository;

    private readonly ApplicationDbContext _dbContext;

    public SignUpService(
        UserManager<Member> userManager,
        RoleManager<ApplicationRole> roleManager,
        IOrganizationRepository organizationRepository,
        ApplicationDbContext dbContext)
    {
        this._userManager = userManager;
        this._roleManager = roleManager;
        this._organizationRepository = organizationRepository;
        this._dbContext = dbContext;
    }

    public async Task<MemberDto> SignUpAdminAsync(SignUpBindingModel input)
    {
        using var transaction = await this._dbContext.Database.BeginTransactionAsync();
        try
        {
            var existingMember = await this._userManager.FindByEmailAsync(input.Email);
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

            await this._organizationRepository.AddOrganizationAsync(new Organization
            {
                OrgId = memberEntity.OrgId,
                OrganizationCode = await this.GenerateUniqueOrgCodeAsync(input.OrganizationName),
                OrganizationName = input.OrganizationName,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });

            var createResult = await this._userManager.CreateAsync(memberEntity, input.Password);

            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException(string.Join("; ", createResult.Errors.Select(e => $"{e.Code}:{e.Description}")));
            }
            else
            {
                var roleName = "Admin";

                if (!await this._roleManager.RoleExistsAsync(roleName))
                {
                    await this._roleManager.CreateAsync(new ApplicationRole(roleName));
                }

                var addToRoleResult = await this._userManager.AddToRoleAsync(memberEntity, roleName);
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

    public async Task<string> GenerateUniqueOrgCodeAsync(string name)
    {
        string BaseSlug(string s) =>
            new string(s.Trim().ToLowerInvariant().Where(ch => char.IsLetterOrDigit(ch) || ch == ' ').ToArray())
            .Replace(' ', '-');

        var baseSlug = BaseSlug(name);
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

    public class EmailAlreadyExistsException : Exception
    {
        public EmailAlreadyExistsException(string message)
            : base(message)
        {
        }
    }
}
