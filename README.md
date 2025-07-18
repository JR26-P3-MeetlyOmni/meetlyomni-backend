# Meetly Omni Backend

This project is a .NET 8 Web API backend supporting the Meetly Omni application. It provides RESTful APIs, database operations, and server-side logic.

## Tech Stack

| Technology            | Description                                                              |
|------------------------|--------------------------------------------------------------------------|
| ASP.NET Core 8         | Backend web framework for building APIs.                                 |
| Entity Framework Core  | ORM for database access and migrations.                                  |
| PostgreSQL             | Relational database used in this project.                                |
| AutoMapper             | For mapping between DTOs and entity models.                              |
| FluentValidation       | For model validation.                                                    |
| xUnit + Moq            | Unit testing framework and mocking library.                              |
| Serilog                | Structured logging to console and files.                                 |
| Swagger (Swashbuckle)  | For auto-generating API documentation.                                   |

## Getting Started

### 1. Set up PostgreSQL

Make sure PostgreSQL is installed and running. Create a database (e.g. MeetlyOmniDb).

Instead of hardcoding credentials in appsettings.Development.json, inject the connection string using .NET User Secrets (for local development) or environment variables (for production).

Set the connection string like this:
```
dotnet user-secrets set "ConnectionStrings:MeetlyOmniDb" "Host=localhost;Port=5432;Database=MeetlyOmniDb;Username=postgres;Password=yourpassword"
```

### 2. Apply EF Core Migrations

Make sure the .NET CLI is installed and EF tools are available. Then run:

```bash
dotnet ef database update
```

This command will apply the migrations and create the necessary schema in your PostgreSQL database.

### 3. Run the Application

To start the backend server in development mode, run:

```bash
dotnet run --project MeetlyOmni.Api
```

The API will be accessible at https://localhost:5001 or http://localhost:5000 depending on your launch settings.

## Available Scripts

| Command                            | Description                                    |
|------------------------------------|------------------------------------------------|
| `dotnet run`                       | Runs the application.                          |
| `dotnet build`                     | Builds the solution.                           |
| `dotnet test`                      | Runs all unit tests.                           |
| `dotnet ef migrations add <Name>` | Creates a new EF Core migration.               |
| `dotnet ef database update`       | Applies the latest migrations to the database. |

## Testing

The solution includes test projects using xUnit and Moq.

To run tests:

```bash
dotnet test
```

## API Documentation

Swagger is enabled. Once the application is running, you can view the API docs at:

[https://localhost:5001/swagger](https://localhost:5001/swagger)

## Project Structure

```
MeetlyOmni.Backend/
├── MeetlyOmni.Api/               # Main Web API project
│   ├── Common/                   # Shared helpers, utilities, extensions
│   ├── Controllers/              # API controllers (route entry points)
│   ├── Data/                     # Data access layer
│   │   ├── Configurations/       # Entity configurations (Fluent API)
│   │   ├── Entities/             # EF Core entity models
│   │   ├── Repository/           # Repository interfaces and implementations
│   │   └── ApplicationDbContext.cs  # EF Core database context
│   ├── Filters/                  # Action and exception filters
│   ├── Mapping/                  # AutoMapper configuration
│   ├── Middlewares/             # Custom middleware components
│   ├── Migrations/              # EF Core migration files
│   ├── Models/                  # View models / DTOs
│   ├── Properties/              # Project properties (e.g., launchSettings.json)
│   ├── Service/                 # Business logic services
│   ├── appsettings.Development.json  # Development environment config
│   ├── appsettings.json         # Default application configuration
│   ├── MeetlyOmni.Api.csproj    # API project file
│   ├── MeetlyOmni.Api.http      # HTTP test requests file
│   └── Program.cs               # Application entry point
├── MeetlyOmni.Tests/            # xUnit test project
│   └── ...                      # Unit test files
├── global.json                  # SDK version configuration
├── MeetlyOmni.sln               # Solution file
├── .gitignore                   # Git ignore rules
└── README.md                    # Project documentation
```