
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src


COPY ./MeetlyOmni.sln ./ 
COPY ./Directory.Packages.props ./  
COPY ./NuGet.config ./               
COPY ./src/MeetlyOmni.Api/*.csproj ./src/MeetlyOmni.Api/

RUN dotnet restore ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj


COPY . .
RUN dotnet publish ./src/MeetlyOmni.Api/MeetlyOmni.Api.csproj \
    -c Release -o /app/publish /p:UseAppHost=false



FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app


ENV DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    ASPNETCORE_URLS=http://0.0.0.0:8080


COPY --from=build /app/publish .

EXPOSE 8080
ENTRYPOINT ["dotnet", "MeetlyOmni.Api.dll"]