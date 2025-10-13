// <copyright file="MediaController.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

using System.Security.Claims;

using Amazon.S3;
using Amazon.S3.Model;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Controllers.Requests;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.PixelFormats;

[ApiController]
[Route("api/v1/media")]
public class MediaController : ControllerBase
{
    private const long _maxFileSize = 5 * 1024 * 1024; // 5 MB
    private static readonly string[] _allowedMimeTypes = { "image/jpeg", "image/png", "image/webp", "image/gif" };

    private readonly IAmazonS3 _s3;
    private readonly AWSOptions _awsOptions;
    private readonly ILogger<MediaController> _logger;
    private readonly IWebHostEnvironment _env;

    public MediaController(IAmazonS3 s3, AWSOptions awsOptions, ILogger<MediaController> logger, IWebHostEnvironment env)
    {
        _s3 = s3;
        _awsOptions = awsOptions;
        _logger = logger;
        _env = env;
    }

    [HttpPost("upload")]
    [Authorize]
    [RequestSizeLimit(_maxFileSize)]
    public async Task<IActionResult> Upload([FromForm] MediaUploadRequest request)
    {
        var file = request.File;
        var orgId = request.OrgId;
        var folder = request.Folder;

        if (file == null || file.Length == 0)
        {
            return BadRequest("File is required.");
        }

        if (orgId == Guid.Empty)
        {
            return BadRequest("orgId is required.");
        }

        if (file.Length > _maxFileSize)
        {
            return StatusCode(413, "File too large.");
        }

        if (!_allowedMimeTypes.Contains(file.ContentType))
        {
            return StatusCode(415, "Unsupported media type.");
        }

        // Optional: Validate image dimensions
        try
        {
            using var img = await Image.LoadAsync(file.OpenReadStream());
            if (img.Width > 6000 || img.Height > 6000)
            {
                return BadRequest("Image dimensions too large.");
            }
        }
        catch (Exception)
        {
            return BadRequest("Invalid image file.");
        }

        // Sanitize filename
        var safeFileName = Path.GetFileNameWithoutExtension(file.FileName)
            .Replace(" ", "_")
            .Replace("\"", string.Empty)
            .Replace("'", string.Empty);
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        var uuid = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var envName = _env.EnvironmentName.ToLowerInvariant();
        var key = $"{envName}/{orgId}/{folder ?? string.Empty}/{now:yyyy}/{now:MM}/{now:dd}/{uuid}_{safeFileName}{ext}".Replace("//", "/");

        var putRequest = new PutObjectRequest
        {
            BucketName = _awsOptions.BucketName,
            Key = key,
            InputStream = file.OpenReadStream(),
            ContentType = file.ContentType,
            CannedACL = S3CannedACL.Private,
            ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256,
            TagSet = new List<Tag>
            {
                new Tag { Key = "app", Value = "meetly" },
                new Tag { Key = "type", Value = "image" },
            },
            Headers =
            {
                CacheControl = "public, max-age=31536000",
            },
        };
        putRequest.Metadata.Add("uploaded-by", User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown"); // Fix: Add metadata after initialization

        PutObjectResponse response;
        try
        {
            response = await _s3.PutObjectAsync(putRequest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "S3 upload failed for user {UserId}, org {OrgId}, file {FileName}", User.FindFirstValue(ClaimTypes.NameIdentifier), orgId, file.FileName);
            return StatusCode(500, "Upload failed.");
        }

        // Generate signed URL (valid for 10 min)
        var urlReq = new GetPreSignedUrlRequest
        {
            BucketName = _awsOptions.BucketName,
            Key = key,
            Expires = DateTime.UtcNow.AddMinutes(10),
            Verb = HttpVerb.GET,
        };
        var signedUrl = _s3.GetPreSignedURL(urlReq);

        // Audit log
        _logger.LogInformation(
            "Image uploaded: user={UserId}, org={OrgId}, key={Key}, size={Size}, ip={IP}, ua={UA}",
            User.FindFirstValue(ClaimTypes.NameIdentifier),
            orgId,
            key,
            file.Length,
            HttpContext.Connection.RemoteIpAddress,
            Request.Headers["User-Agent"].ToString());

        return Created(string.Empty, new
        {
            key,
            url = signedUrl,
            etag = response.ETag,
            contentType = file.ContentType,
            size = file.Length,
        });
    }

    [HttpPut("reupload")]
    [Authorize]
    [RequestSizeLimit(_maxFileSize)]
    public async Task<IActionResult> Reupload([FromForm] ReuploadMediaRequest request)
    {
        var file = request.File;
        var key = request.Key;      // the original key to be replaced
        var orgId = request.OrgId;

        if (file == null || file.Length == 0)
        {
            return BadRequest("File is required.");
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            return BadRequest("key is required.");
        }

        if (orgId == Guid.Empty)
        {
            return BadRequest("orgId is required.");
        }

        if (file.Length > _maxFileSize)
        {
            return StatusCode(413, "File too large.");
        }

        if (!_allowedMimeTypes.Contains(file.ContentType))
        {
            return StatusCode(415, "Unsupported media type.");
        }

        // file content validation
        using var img = await Image.LoadAsync(file.OpenReadStream());
        if (img.Width > 6000 || img.Height > 6000)
        {
            return BadRequest("Image dimensions too large.");
        }

        img.Metadata.ExifProfile = null;

        // authorization: ensure the key belongs to the specified org
        var envName = _env.EnvironmentName.ToLowerInvariant();
        var orgKeyPrefix = $"{envName}/{orgId}/";
        if (!key.StartsWith(orgKeyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return Forbid("Key does not belong to the specified org.");
        }

        // delete the old file if exists
        try
        {
            await _s3.DeleteObjectAsync(_awsOptions.BucketName, key);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // file not found, can ignore
        }

        // generate new key with same directory path
        var directoryPath = Path.GetDirectoryName(key)?.Replace("\\", "/"); // get directory path
        var safeFileName = Path.GetFileNameWithoutExtension(file.FileName)
            .Replace(" ", "_")
            .Replace("\"", string.Empty)
            .Replace("'", string.Empty);
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        var uuid = Guid.NewGuid();
        key = $"{directoryPath}/{uuid}_{safeFileName}{ext}";

        // upload the new file
        var putRequest = new PutObjectRequest
        {
            BucketName = _awsOptions.BucketName,
            Key = key,
            InputStream = file.OpenReadStream(),
            ContentType = file.ContentType,
            CannedACL = S3CannedACL.Private,
            ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256,
            TagSet = new List<Tag>
        {
            new Tag { Key = "app", Value = "meetly" },
            new Tag { Key = "type", Value = "image" },
        },
            Headers =
        {
            CacheControl = "public, max-age=31536000",
        },
        };
        putRequest.Metadata.Add("uploaded-by", User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown");

        PutObjectResponse response;
        try
        {
            response = await _s3.PutObjectAsync(putRequest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "S3 reupload failed for user {UserId}, org {OrgId}, key {Key}, file {FileName}", User.FindFirstValue(ClaimTypes.NameIdentifier), orgId, key, file.FileName);
            return StatusCode(500, "Reupload failed.");
        }

        // generate signed URL (valid for 10 min)
        var urlReq = new GetPreSignedUrlRequest
        {
            BucketName = _awsOptions.BucketName,
            Key = key,
            Expires = DateTime.UtcNow.AddMinutes(10),
            Verb = HttpVerb.GET,
        };
        var signedUrl = _s3.GetPreSignedURL(urlReq);

        // detailed audit log
        _logger.LogInformation(
            "Image reuploaded: user={UserId}, org={OrgId}, key={Key}, etag={ETag}, size={Size}, ip={IP}, ua={UA}",
            User.FindFirstValue(ClaimTypes.NameIdentifier),
            orgId,
            key,
            response.ETag,
            file.Length,
            HttpContext.Connection.RemoteIpAddress,
            Request.Headers["User-Agent"].ToString());

        return Ok(new
        {
            key,
            url = signedUrl,
            etag = response.ETag,
            contentType = file.ContentType,
            size = file.Length,
        });
    }
}
