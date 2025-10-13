// <copyright file="InvitationService.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using MeetlyOmni.Api.Common.Constants;
using MeetlyOmni.Api.Common.Enums.EmailType;
using MeetlyOmni.Api.Data;
using MeetlyOmni.Api.Data.Entities;
using MeetlyOmni.Api.Data.Repository.Interfaces;
using MeetlyOmni.Api.Filters;
using MeetlyOmni.Api.Models.Auth;
using MeetlyOmni.Api.Models.Invitation;
using MeetlyOmni.Api.Service.AuthService.Interfaces;
using MeetlyOmni.Api.Service.Email;
using MeetlyOmni.Api.Service.Email.Interfaces;
using MeetlyOmni.Api.Service.Invitation.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace MeetlyOmni.Api.Service.Invitation;

/// <summary>
/// Service for managing member invitations to organizations.
/// </summary>
public class InvitationService : IInvitationService
{
    private readonly UserManager<Member> _userManager;
    private readonly IOrganizationRepository _organizationRepository;
    private readonly ApplicationDbContext _dbContext;
    private readonly IEmailLinkService _emailLinkService;
    private readonly IEmailTemplateService _emailTemplateService;
    private readonly IEmailSender _emailSender;
    private readonly ITokenService _tokenService;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<InvitationService> _logger;

    public InvitationService(
        UserManager<Member> userManager,
        IOrganizationRepository organizationRepository,
        ApplicationDbContext dbContext,
        IEmailLinkService emailLinkService,
        IEmailTemplateService emailTemplateService,
        IEmailSender emailSender,
        ITokenService tokenService,
        RoleManager<ApplicationRole> roleManager,
        ILogger<InvitationService> logger)
    {
        _userManager = userManager;
        _organizationRepository = organizationRepository;
        _dbContext = dbContext;
        _emailLinkService = emailLinkService;
        _emailTemplateService = emailTemplateService;
        _emailSender = emailSender;
        _tokenService = tokenService;
        _roleManager = roleManager;
        _logger = logger;
    }

    public async Task<InviteMemberResponse> InviteMemberAsync(
        string email,
        string? message,
        Guid orgId,
        Guid invitedByUserId,
        CancellationToken ct = default)
    {
        // Validate organization exists
        var organization = await _organizationRepository.GetByIdAsync(orgId, ct);
        if (organization == null)
        {
            return new InviteMemberResponse
            {
                Success = false,
                Message = "Organization not found.",
                Email = email,
            };
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null)
        {
            if (existingUser.OrgId == orgId)
            {
                return new InviteMemberResponse
                {
                    Success = false,
                    Message = "User is already a member of this organization.",
                    Email = email,
                };
            }
            else
            {
                return new InviteMemberResponse
                {
                    Success = false,
                    Message = "User is already a member of another organization.",
                    Email = email,
                };
            }
        }

        // Generate invitation token
        var invitationToken = await _emailLinkService.GenerateInvitationTokenAsync(email, orgId, ct);

        // Send invitation email
        await SendInvitationEmailAsync(email, organization.OrganizationName, message, invitationToken, ct);

        _logger.LogInformation("Invitation sent to {Email} for organization {OrgId}", email, orgId);

        return new InviteMemberResponse
        {
            Success = true,
            Message = "Invitation sent successfully.",
            Email = email,
        };
    }

    public async Task<AcceptInvitationResponse> AcceptInvitationAsync(
        AcceptInvitationRequest request,
        CancellationToken ct = default)
    {
        // Validate invitation token
        var isValidToken = await ValidateInvitationTokenAsync(request.Email, request.Token, ct);
        if (!isValidToken)
        {
            return new AcceptInvitationResponse
            {
                Success = false,
                Message = "Invalid or expired invitation token.",
            };
        }

        // Get organization ID from token
        var orgId = await _emailLinkService.GetOrganizationIdFromInvitationTokenAsync(request.Token, ct);
        if (orgId == null)
        {
            return new AcceptInvitationResponse
            {
                Success = false,
                Message = "Invalid invitation token.",
            };
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            return new AcceptInvitationResponse
            {
                Success = false,
                Message = "User already exists. Please use login instead.",
            };
        }

        // Assign LocalMemberNumber = max + 1 (per organization) with transaction and single retry on conflict
        Member? user = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var tx = await _dbContext.Database.BeginTransactionAsync(ct);
            try
            {
                var currentMax = await _dbContext.Users
                    .Where(m => m.OrgId == orgId.Value)
                    .MaxAsync(m => (int?)m.LocalMemberNumber, ct) ?? 0;

                user = new Member
                {
                    Id = Guid.NewGuid(),
                    Email = request.Email,
                    UserName = request.Email,
                    OrgId = orgId.Value,
                    LocalMemberNumber = currentMax + 1,
                    EmailConfirmed = true, // Auto-confirm for invited users
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };

                var result = await _userManager.CreateAsync(user, request.Password);
                if (!result.Succeeded)
                {
                    await tx.RollbackAsync(ct);
                    return new AcceptInvitationResponse
                    {
                        Success = false,
                        Message = string.Join(", ", result.Errors.Select(e => e.Description)),
                    };
                }

                // Ensure default role exists and assign to the invited user
                const string defaultRole = RoleConstants.Employee;
                if (!await _roleManager.RoleExistsAsync(defaultRole))
                {
                    var created = await _roleManager.CreateAsync(new ApplicationRole(defaultRole));
                    if (!created.Succeeded)
                    {
                        await tx.RollbackAsync(ct);
                        return new AcceptInvitationResponse
                        {
                            Success = false,
                            Message = string.Join(", ", created.Errors.Select(e => e.Description)),
                        };
                    }
                }

                var addRoleResult = await _userManager.AddToRoleAsync(user, defaultRole);
                if (!addRoleResult.Succeeded)
                {
                    await tx.RollbackAsync(ct);
                    return new AcceptInvitationResponse
                    {
                        Success = false,
                        Message = string.Join(", ", addRoleResult.Errors.Select(e => e.Description)),
                    };
                }

                await _dbContext.SaveChangesAsync(ct);
                await tx.CommitAsync(ct);
                break; // success
            }
            catch (DbUpdateException)
            {
                await tx.RollbackAsync(ct);
                if (attempt == 1)
                {
                    return new AcceptInvitationResponse
                    {
                        Success = false,
                        Message = "Failed to assign member number due to concurrency. Please retry.",
                    };
                }
            }
        }

        // Generate login tokens
        var loginResponse = await _tokenService.GenerateTokensAsync(user);

        _logger.LogInformation("User {Email} accepted invitation and joined organization {OrgId}", request.Email, orgId);

        return new AcceptInvitationResponse
        {
            Success = true,
            Message = "Invitation accepted successfully.",
            LoginResponse = loginResponse,
        };
    }

    public async Task<bool> ValidateInvitationTokenAsync(string email, string token, CancellationToken ct = default)
    {
        try
        {
            return await _emailLinkService.ValidateInvitationTokenAsync(email, token, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate invitation token for {Email}", email);
            return false;
        }
    }

    private async Task SendInvitationEmailAsync(
        string email,
        string organizationName,
        string? message,
        string invitationToken,
        CancellationToken ct)
    {
        var invitationLink = $"{_emailLinkService.GetBaseUrl()}/accept-invitation?token={Uri.EscapeDataString(invitationToken)}&email={Uri.EscapeDataString(email)}";

        var emailMessage = _emailTemplateService.Build(
            EmailType.MemberInvitation,
            email,
            new Dictionary<string, string>
            {
                ["organizationName"] = organizationName,
                ["invitationLink"] = invitationLink,
                ["message"] = message ?? string.Empty,
            });

        await _emailSender.SendAsync(emailMessage, ct);
    }
}
