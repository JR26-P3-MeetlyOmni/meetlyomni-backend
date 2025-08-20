# syntax=docker/dockerfile:1.7

############################
# 1) Build/Publish stage
############################
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# 只拷贝 csproj 并还原依赖（充分利用缓存）
COPY ./src/MeetlyOmni.Api/*.csproj ./src/MeetlyOmni.Api/
RUN dotnet restore ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj

# 再拷贝其余源码并发布
COPY . .
RUN dotnet publish ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj \
    -c Release -o /app/publish /p:UseAppHost=false

############################
# 2) Runtime stage
############################
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# 运行时仅拷贝发布产物（镜像小、安全面更小）
COPY --from=build /app/publish .

# 在容器里监听 8080（可改为 80；用 8080 在 K8s/ALB 上更常见）
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080

# 可选：健康检查（容器内自检；K8s/ALB 仍建议用 /healthz 探针）
# HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
#   CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["dotnet", "MeetlyOmni.Api.dll"]