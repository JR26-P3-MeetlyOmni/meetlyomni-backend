FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# Copy solution and project files first to leverage Docker layer caching
COPY MeetlyOmni.sln ./
COPY src/MeetlyOmni.Api/MeetlyOmni.Api.csproj src/MeetlyOmni.Api/
COPY src/MeetlyOmni.IntegrationTests/MeetlyOmni.IntegrationTests.csproj src/MeetlyOmni.IntegrationTests/
COPY src/MeetlyOmni.Unit.tests/MeetlyOmni.Unit.tests.csproj src/MeetlyOmni.Unit.tests/

# Restore all projects
RUN dotnet restore MeetlyOmni.sln

# Copy the remaining source code
COPY . .

# Publish the API project
RUN dotnet publish src/MeetlyOmni.Api/MeetlyOmni.Api.csproj -c Release -o /app/publish --no-restore

# Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Listen on HTTP only inside container
ENV ASPNETCORE_URLS=http://0.0.0.0:8080

EXPOSE 8080

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "MeetlyOmni.Api.dll"]