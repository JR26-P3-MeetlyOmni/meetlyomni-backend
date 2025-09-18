# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Set working directory to root
WORKDIR /app

# Copy solution and project files
COPY ["MeetlyOmni.sln", "./"]
COPY ["src/MeetlyOmni.Api/MeetlyOmni.Api.csproj", "./"]

# Restore dependencies
RUN dotnet restore "MeetlyOmni.Api.csproj"

# Install EF tools
RUN dotnet tool install --global dotnet-ef
ENV PATH="$PATH:/root/.dotnet/tools"

# Copy all source files
COPY . .

# Set working directory to root
WORKDIR /app

# Debug: Final verification
RUN echo "=== Final working directory ===" && pwd
RUN echo "=== Final directory listing ===" && ls -la

# Build with detailed output
RUN echo "=== Starting build ==="
RUN dotnet build "src/MeetlyOmni.Api/MeetlyOmni.Api.csproj" -c Release -o /app/build --verbosity detailed

# Publish - removed --no-build flag
RUN echo "=== Starting publish ==="
RUN dotnet publish "src/MeetlyOmni.Api/MeetlyOmni.Api.csproj" -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:80

EXPOSE 80

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "MeetlyOmni.Api.dll"]
