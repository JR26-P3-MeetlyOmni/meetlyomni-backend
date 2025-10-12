using Amazon.S3;
using Amazon.S3.Model;

using MeetlyOmni.Api.Common.Options;
using MeetlyOmni.Api.Controllers.Requests;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

using Xunit;

public class MediaControllerTests
{
    [Fact]
    public async Task Upload_InvalidMimeType_UsesConfiguredBucket_Returns415()
    {
        var awsOptions = new AWSOptions { BucketName = "meetlyomni_media", Region = Amazon.RegionEndpoint.APSoutheast2 }; // match appsettings.json
        var s3Mock = new Mock<IAmazonS3>();
        var loggerMock = new Mock<ILogger<MediaController>>();
        var envMock = new Mock<IWebHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName).Returns("Test");

        var controller = new MediaController(s3Mock.Object, awsOptions, loggerMock.Object, envMock.Object);

        var fileMock = new Mock<IFormFile>();
        fileMock.Setup(f => f.Length).Returns(1000);
        fileMock.Setup(f => f.ContentType).Returns("application/pdf");
        fileMock.Setup(f => f.FileName).Returns("file.pdf");

        var request = new MediaUploadRequest
        {
            File = fileMock.Object,
            OrgId = Guid.NewGuid(),
            Folder = "events/covers"
        };

        var result = await controller.Upload(request);

        var statusResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(415, statusResult.StatusCode);
    }
}

