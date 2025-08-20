
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src


COPY .config/dotnet-tools.json ./.config/dotnet-tools.json
RUN dotnet tool restore || true


COPY ./MeetlyOmni.sln ./
COPY ./src/MeetlyOmni.Api/*.csproj ./src/MeetlyOmni.Api/
RUN dotnet restore ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj


COPY . .
RUN dotnet publish ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj \
    -c Release --no-restore -o /app/publish /p:UseAppHost=false


FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://0.0.0.0:80

COPY --from=build /app/publish .

EXPOSE 80
ENTRYPOINT ["dotnet", "MeetlyOmni.Api.dll"]