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

The `.env` file contains all necessary environment variables for local development. Key configurations:

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
