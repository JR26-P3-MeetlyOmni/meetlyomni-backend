# MeetlyOmni Backend

This project is a .NET 8 Web API backend supporting the Meetly Omni application. It provides RESTful APIs, database operations, and server-side logic.

## 🚀 Quick Start

**New to this project?** Follow our comprehensive [Setup Guide](./SETUP-GUIDE.md) to get everything running locally.

### For Experienced Developers

```bash
# Quick setup (assumes PostgreSQL is running)
git clone <repository-url>
cd MeetlyOmni/meetlyomni-backend
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=meetlyomni_dev;Username=your_user;Password=your_password"
dotnet ef database update --project src/MeetlyOmni.Api
dotnet run --project src/MeetlyOmni.Api
```

## Technology Stack

- **.NET 8**: The latest long-term support version of .NET
- **ASP.NET Core**: Web API framework
- **Entity Framework Core**: Object-Relational Mapping (ORM)
- **PostgreSQL**: Primary database
- **AutoMapper**: Object-to-object mapping
- **StyleCop.Analyzers**: Code style analysis and enforcement

## Project Structure

```
src/
├── MeetlyOmni.Api/
│   ├── Common/
│   │   ├── Constants/          # Application constants
│   │   ├── Enums/             # Enumeration definitions
│   │   └── Extensions/        # Extension methods
│   ├── Controllers/           # API controllers
│   ├── Data/
│   │   ├── Entities/          # Database entity models
│   │   ├── Configurations/    # Entity Framework configurations
│   │   └── Repository/        # Data access layer
│   ├── Filters/              # Action filters
│   ├── Mapping/              # AutoMapper profiles
│   ├── Middlewares/          # Custom middleware
│   ├── Migrations/           # Database migrations
│   ├── Models/               # DTOs and view models
│   ├── Service/              # Business logic services
│   └── Program.cs            # Application entry point
└── README.md                    # Project documentation
```

## Git Hooks Setup

This project uses Git pre-commit hooks to ensure code quality. New team members need to set up the hooks after cloning the repository.

### Setup Instructions

1. **Set up Git hooks** (required for new team members):

   ```powershell
   .\setup-git-hooks.ps1
   ```

2. **Test hooks** (optional, to verify setup):
   ```powershell
   .\test-git-hooks.ps1
   ```

### What the hooks do

The pre-commit hook automatically runs before each commit:

- **Code formatting**: `dotnet format MeetlyOmni.sln`
- **Build validation**: `dotnet build MeetlyOmni.sln --no-restore`
- **Unit testing**: `dotnet test MeetlyOmni.sln --no-build`

If any step fails, the commit will be blocked until issues are resolved.

## API Documentation

Once running, visit:

- **Swagger UI**: https://localhost:5001/swagger
- **Health Check**: https://localhost:5001/health

## Contributing

1. Follow the [Setup Guide](./SETUP-GUIDE.md) to configure your environment
2. Create a feature branch from `main`
3. Make your changes with appropriate tests
4. Ensure all Git hooks pass
5. Submit a pull request with a clear description

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

## Docker Compose Usage

### 0. What does this Docker Compose include?

This Docker Compose setup includes the following services:

- **API Service**: The .NET 8 Web API for Meetly Omni.
- **Database (PostgreSQL)**: A PostgreSQL database instance.
- **SQL Query Tool (Adminer)**: A web-based database management tool.

### 1. Benefits of Using Docker Compose

Using Docker Compose to start the API service, database, and Adminer has several advantages over setting them up individually:

- **Simplified Setup**: Easily start all services with a single command.
- **Consistency**: Ensures the same environment across different development machines.
- **Isolation**: Runs each service in its own container, avoiding conflicts.

### 2. How to Use Docker Compose

**Pre-requisite**: Make sure Docker Desktop is installed and running.

To start the services, run the following command in the project root:

```bash
docker-compose up -d
```

This command will start all the services in detached mode.

### 3. Accessing Services

- **Adminer**: Once the services are up, you can access Adminer at `http://localhost:8081`. Use the following credentials to connect to the PostgreSQL database:

  - **System**: PostgreSQL
  - **Server**: db
  - **Username**: (your database username)
  - **Password**: (your database password)
  - **Database**: (your database name)

- # **API Swagger**: The API documentation is available at `http://localhost:5000/swagger`. You can use this interface to explore and test the API endpoints.

## Support

- 📖 **Setup Issues**: See [SETUP-GUIDE.md](./SETUP-GUIDE.md)
- 🐛 **Bugs**: Create an issue with reproduction steps
- 💡 **Feature Requests**: Discuss with the team first
