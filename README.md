# MeetlyOmni Backend

.NET 8 Web API backend for the Meetly Omni application.

## 🚀 Quick Setup

### 1. Clone and Setup Git Hooks

```bash
git clone <repository-url>
cd meetlyomni-backend

# Setup Git hooks (required for new team members)
.\setup-git-hooks-final.ps1
```

### 2. Configure Database Connection

```bash
# Set database connection string
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=meetlyomni_dev;Username=your_user;Password=your_password"

# View all user-secrets
dotnet user-secrets list
```

### 3. Update Database

```bash
# Apply database migrations
dotnet ef database update --project src/MeetlyOmni.Api
```

### 4. Run the Application

```bash
dotnet run --project src/MeetlyOmni.Api
```

## 📋 Useful Commands

### Git Hooks

- **Setup hooks**: `.\setup-git-hooks-final.ps1`
- **Pre-commit**: Auto-formats code and runs build
- **Pre-push**: Runs tests and coverage checks
- macOS: `bash setup-git-hooks-mac.sh`

### User Secrets

- **Set secret**: `dotnet user-secrets set "Key" "Value"`
- **List secrets**: `dotnet user-secrets list`
- **Remove secret**: `dotnet user-secrets remove "Key"`
- **Clear all**: `dotnet user-secrets clear`

### Database

- **Update**: `dotnet ef database update --project src/MeetlyOmni.Api`
- **Add migration**: `dotnet ef migrations add MigrationName --project src/MeetlyOmni.Api`
- **Remove migration**: `dotnet ef migrations remove --project src/MeetlyOmni.Api

## 🔗 API Documentation

- **Swagger UI**: https://localhost:5001/swagger
- **Health Check**: https://localhost:5001/health

## 🐳 Docker Compose (Optional)

```bash
# Start all services (API, PostgreSQL, Adminer)
docker-compose up -d

# Access Adminer: http://localhost:8081
# Access Swagger: http://localhost:5000/swagger
```

## 📁 Project Structure

```
src/MeetlyOmni.Api/
├── Controllers/          # API endpoints
├── Data/                # Database entities & context
├── Service/             # Business logic
├── Models/              # DTOs
└── Common/              # Shared utilities
```

## 🛠 Technology Stack

- **.NET 8** - Framework
- **Entity Framework Core** - ORM
- **PostgreSQL** - Database
- **AutoMapper** - Object mapping
- **StyleCop** - Code analysis

