# 🚀 MeetlyOmni Backend Setup Guide

This guide will help new team members set up the MeetlyOmni backend project on their local machine.

## 📋 Prerequisites

Before starting, ensure you have the following installed:

### Required Software
- **Visual Studio 2022** or **Visual Studio Code** with C# extension
- **.NET 8 SDK** - [Download here](https://dotnet.microsoft.com/download/dotnet/8.0)
- **PostgreSQL 15+** - [Download here](https://www.postgresql.org/download/)
- **Git** - [Download here](https://git-scm.com/downloads)

### Verify Installations
```bash
# Check .NET version
dotnet --version
# Should show 8.0.x

# Check PostgreSQL
psql --version
# Should show PostgreSQL 15.x or higher

# Check Git
git --version
```

## 🔄 Step-by-Step Setup

### Step 1: Clone the Repository
```bash
# Clone the project
git clone <repository-url>
cd MeetlyOmni/meetlyomni-backend

# Verify project structure
ls -la
# You should see: src/, global.json, MeetlyOmni.sln, README.md, etc.
```

### Step 2: PostgreSQL Database Setup

#### 2.1 Start PostgreSQL Service
```bash
# Windows (if installed as service)
# PostgreSQL should start automatically

# macOS (using Homebrew)
brew services start postgresql

# Linux (Ubuntu/Debian)
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### 2.2 Create Database and User
```bash
# Connect to PostgreSQL as superuser
psql -U postgres

# In PostgreSQL prompt, create database and user:
CREATE DATABASE meetlyomni_dev;
CREATE USER meetlyomni_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE meetlyomni_dev TO meetlyomni_user;
GRANT ALL ON SCHEMA public TO meetlyomni_user;

# Exit PostgreSQL
\q
```

#### 2.3 Test Database Connection
```bash
# Test connection with new user
psql -U meetlyomni_user -d meetlyomni_dev -h localhost

# If successful, you'll see the database prompt
# Exit with: \q
```

### Step 3: Configure Connection String

#### 3.1 Using User Secrets (Recommended for Development)
```bash
# Navigate to the API project directory
cd src/MeetlyOmni.Api

# Initialize user secrets
dotnet user-secrets init

# Set the connection string (replace with your actual password)
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=meetlyomni_dev;Username=meetlyomni_user;Password=your_secure_password"

# Verify the secret was set
dotnet user-secrets list
```

#### 3.2 Alternative: Environment Variables
```bash
# Windows PowerShell
$env:ConnectionStrings__DefaultConnection = "Host=localhost;Port=5432;Database=meetlyomni_dev;Username=meetlyomni_user;Password=your_secure_password"

# macOS/Linux Bash
export ConnectionStrings__DefaultConnection="Host=localhost;Port=5432;Database=meetlyomni_dev;Username=meetlyomni_user;Password=your_secure_password"
```

#### 3.3 Verify Connection String Format
Your connection string should look like:
```
Host=localhost;Port=5432;Database=meetlyomni_dev;Username=meetlyomni_user;Password=your_secure_password
```

### Step 4: Install Dependencies and Build
```bash
# From the solution root (meetlyomni-backend/)
dotnet restore

# Build the solution
dotnet build

# Verify build succeeded (should show "Build succeeded")
```

### Step 5: Apply Database Migrations

#### 5.1 Install EF Core Tools (if not already installed)
```bash
dotnet tool install --global dotnet-ef
# or update if already installed
dotnet tool update --global dotnet-ef
```

#### 5.2 Apply Migrations
```bash
# From solution root, apply migrations
dotnet ef database update --project src/MeetlyOmni.Api

# You should see output like:
# "Applying migration '20250717020620_InitialCreate'"
# "Applying migration '20250718043555_Add 6 more entities'"
# "Applying migration '20250722072819_AddMissingConstraintsAndIndexes'"
# "Applying migration '20250723041643_MemberUuidMigrationFixed'"
# "Done."
```

#### 5.3 Verify Database Schema
```bash
# Connect to database and check tables
psql -U meetlyomni_user -d meetlyomni_dev -h localhost

# List tables
\dt

# You should see tables like:
# Members, Organizations, Games, Events, etc.

# Exit
\q
```

### Step 6: Set Up Git Hooks (Code Quality)
```bash
# Run the setup script
.\setup-git-hooks.ps1

# Test the hooks
.\test-git-hooks.ps1

# You should see:
# "Git hooks setup completed!"
# "Hook testing completed! You can now commit code normally."
```

### Step 7: Run the Application

#### 7.1 Start the Development Server
```bash
# From solution root
dotnet run --project src/MeetlyOmni.Api

# Or from the API project directory
cd src/MeetlyOmni.Api
dotnet run
```

#### 7.2 Verify Application is Running
You should see output like:
```
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:5001
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5000
```

#### 7.3 Test API Endpoints
Open your browser and navigate to:
- **Swagger UI**: https://localhost:5001/swagger
- **Health Check**: https://localhost:5001/health

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Issue: "Connection string not found"
**Solution**: Verify user secrets or environment variables are set correctly
```bash
# Check user secrets
cd src/MeetlyOmni.Api
dotnet user-secrets list

# Should show your connection string
```

#### Issue: "Login failed for user"
**Solution**: Check PostgreSQL user permissions
```sql
-- Connect as postgres superuser and grant permissions
GRANT ALL PRIVILEGES ON DATABASE meetlyomni_dev TO meetlyomni_user;
GRANT ALL ON SCHEMA public TO meetlyomni_user;
GRANT USAGE ON SCHEMA public TO meetlyomni_user;
```

#### Issue: "Could not connect to the database"
**Solution**: Verify PostgreSQL is running and connection details
```bash
# Check PostgreSQL status
# Windows: Check Services or Task Manager
# macOS: brew services list | grep postgresql
# Linux: sudo systemctl status postgresql

# Test connection manually
psql -U meetlyomni_user -d meetlyomni_dev -h localhost -p 5432
```

#### Issue: "Migration failed"
**Solution**: Check database permissions and existing data
```bash
# Check if migrations table exists
psql -U meetlyomni_user -d meetlyomni_dev -c "\dt"

# If you see migration errors, you may need to reset the database
# (WARNING: This will delete all data)
dropdb -U postgres meetlyomni_dev
createdb -U postgres meetlyomni_dev
# Then rerun migrations
```

#### Issue: "dotnet ef command not found"
**Solution**: Install EF Core tools
```bash
dotnet tool install --global dotnet-ef
# Restart your terminal and try again
```

## 🎯 Development Workflow

### Daily Development
1. **Pull latest changes**: `git pull origin main`
2. **Apply new migrations**: `dotnet ef database update --project src/MeetlyOmni.Api`
3. **Build and test**: `dotnet build && dotnet test`
4. **Run application**: `dotnet run --project src/MeetlyOmni.Api`

### Before Committing
The Git hooks will automatically:
- Format your code (`dotnet format`)
- Build the solution (`dotnet build`)
- Run tests (`dotnet test`)

If any step fails, the commit will be blocked until issues are resolved.

## 📚 Additional Resources

- **Entity Framework Core**: https://docs.microsoft.com/en-us/ef/core/
- **ASP.NET Core**: https://docs.microsoft.com/en-us/aspnet/core/
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/

## 🆘 Getting Help

If you encounter issues not covered in this guide:

1. **Check the logs** in your terminal output
2. **Review existing issues** in the project repository
3. **Ask the team** in your development chat/channel
4. **Create a new issue** with detailed error messages and steps to reproduce

---

🎉 **Welcome to the MeetlyOmni team!** You're now ready to contribute to the project. 