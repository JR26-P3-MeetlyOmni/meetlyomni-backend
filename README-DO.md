# MeetlyOmni Docker Compose Setup

This Docker Compose setup allows you to run the MeetlyOmni application locally with all services containerized.

## Project Structure

The Docker Compose configuration is located in the `meetlyomni-backend/` folder:
- `meetlyomni-backend/docker-compose.yml` - Main Docker Compose configuration
- `meetlyomni-backend/.env` - Environment variables
- `meetlyomni-frontend/` - Frontend application
- `meetlyomni-backend/` - Backend API and database

## Services

- **Frontend**: Next.js application running on `http://localhost:3000`
- **Backend API**: .NET 8 API running on `http://localhost:5000`
- **Database**: PostgreSQL database running on `localhost:5432`
- **Adminer**: Database administration interface running on `http://localhost:8081`

## Prerequisites

- Docker Desktop installed and running
- Docker Compose

## Quick Start

1. **Navigate to the backend folder**:
   ```bash
   cd meetlyomni-backend
   ```

2. **Start all services**:
   ```bash
   docker-compose up --build
   ```

3. **Access the applications**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000
   - Database Admin: http://localhost:8081

4. **Stop all services**:
   ```bash
   docker-compose down
   ```

**Alternative commands (from backend folder)**:
```bash
# Start in detached mode
docker-compose up -d

# View container status
docker-compose ps

# View logs
docker-compose logs

# Stop and remove containers
docker-compose down
```

## Environment Configuration

The `.env` file contains all necessary environment variables for local development. Here's the complete configuration:

```env
# Database Configuration
DB_NAME=meetlyomni_dev
DB_USER=postgres
DB_PASS=password123

# Backend API Configuration
ASPNETCORE_ENVIRONMENT=Development
ConnectionStrings__MeetlyOmniDb=Host=db;Port=5432;Database=${DB_NAME};Username=${DB_USER};Password=${DB_PASS}

# JWT Configuration
Jwt__Issuer=MeetlyOmni-API
Jwt__Audience=localhost3000
Jwt__AccessTokenExpirationMinutes=15
Jwt__RefreshTokenExpirationMinutes=43200

# CORS Configuration
Cors__AllowedOrigins__0=http://localhost:3000
Cors__AllowedOrigins__1=https://localhost:3000
Cors__AllowedOrigins__2=http://frontend:3000

# Frontend URLs
Frontend__BaseUrl=http://localhost:3000
Backend__ApiBaseUrl=http://localhost:5000/api/v1.0

# Frontend Environment Variables
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000/api/v1.0

# Database Performance Settings
POSTGRES_SHARED_BUFFERS=512MB
POSTGRES_MAX_CONNECTIONS=20
```

**Key configurations:**
- Database credentials
- JWT settings
- CORS origins
- API URLs

## Database Access

- **Host**: `localhost`
- **Port**: `5432`
- **Database**: `meetlyomni_dev`
- **Username**: `postgres`
- **Password**: `password123`

Use Adminer at http://localhost:8081 to manage the database:
- System: PostgreSQL
- Server: `db`
- Username: `postgres`
- Password: `password123`
- Database: `meetlyomni_dev`

## Test Account

For testing purposes, a verified test account is available:

- **Email**: `test@example.com`
- **Password**: `Test123!`
- **Status**: Email confirmed and active

This account can be used to log in to the application without requiring email verification.

## Cloud Deployment Preparation

This Docker Compose setup is designed to be easily deployable to cloud providers like DigitalOcean:

- **Containerized Architecture**: All services are containerized for easy deployment
- **Environment Variables**: Centralized configuration for different environments
- **Database Persistence**: PostgreSQL data is persisted in Docker volumes
- **Health Checks**: Services include health monitoring for production readiness
