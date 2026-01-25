# Enhanced Full-Stack Architecture for Behavioral Sentinel EDR Tool

## Overview

This document outlines the enhanced architecture for transforming the existing Python-based EDR monitoring tool into a modern web-based dashboard application. The current system consists of a monitoring script (`first.py`), a Tkinter GUI (`first_gui.py`), and a FastAPI backend with SQLite database (`first_database_api.py`). The new architecture replaces the desktop GUI with a responsive web frontend while maintaining and enhancing the backend components.

## Technology Stack

### Frontend
- **Framework**: React 18+ with TypeScript
- **UI Library**: Material-UI (MUI) for consistent, professional components
- **State Management**: Redux Toolkit for complex state management
- **HTTP Client**: Axios for API communication
- **Build Tool**: Vite for fast development and optimized production builds
- **Deployment**: Static hosting (e.g., Nginx, Vercel, or Netlify)

### Backend
- **Framework**: FastAPI (retained from existing implementation)
- **Language**: Python 3.8+
- **ASGI Server**: Uvicorn
- **Authentication**: JWT-based authentication for secure API access
- **Background Tasks**: APScheduler for periodic monitoring tasks
- **Logging**: Structured logging with Python's logging module

### Database
- **Primary Database**: SQLite (retained for lightweight deployment)
- **Alternative**: PostgreSQL for enterprise deployments requiring concurrent access and advanced querying
- **ORM**: SQLAlchemy for database operations and migrations
- **Migration Tool**: Alembic for schema versioning

### API
- **Style**: RESTful API with OpenAPI/Swagger documentation
- **Serialization**: Pydantic for request/response validation
- **CORS**: Configurable CORS middleware for cross-origin requests
- **Rate Limiting**: Optional rate limiting for API endpoints

### Additional Tools
- **Containerization**: Docker and Docker Compose for consistent deployment
- **Monitoring**: Prometheus and Grafana for system monitoring
- **Testing**: Pytest for backend, Jest for frontend
- **CI/CD**: GitHub Actions for automated testing and deployment

## Component Breakdown

### Frontend Components

#### Core Layout
- **App**: Main application component with routing
- **Navigation**: Sidebar or top navigation with tabs for different views
- **Header**: Status indicator, risk score display, and user controls

#### Dashboard Components
- **RiskScoreWidget**: Large display of current risk score with color coding
- **AlertSummary**: Summary cards showing recent alerts by category
- **Charts**: Real-time charts for risk trends, alert frequency, and system metrics
- **StatusIndicator**: System health and monitoring status

#### Monitoring Components
- **FileSystemMonitor**: Table/list of file system events with filtering and sorting
- **ProcessMonitor**: Process list with CPU/memory usage and new process alerts
- **NetworkMonitor**: Active connections table with process association
- **LogViewer**: Unified log viewer with search and filtering capabilities

#### Configuration Components
- **Settings**: User preferences, alert thresholds, and monitoring parameters
- **MalwareHashes**: Interface for managing known malicious hashes
- **WatchPaths**: Configuration of monitored directories

### Backend Modules

#### Core Modules
- **monitor.py**: Core monitoring logic (adapted from `first.py`)
  - File system monitoring
  - Process monitoring
  - Network monitoring
  - Camera/microphone detection
- **database.py**: Database connection and session management
- **models.py**: SQLAlchemy models for database entities
- **schemas.py**: Pydantic schemas for API validation
- **auth.py**: Authentication and authorization logic

#### API Modules
- **routes/alerts.py**: Alert management endpoints
- **routes/monitoring.py**: Monitoring control and status endpoints
- **routes/config.py**: Configuration management endpoints
- **dependencies.py**: FastAPI dependencies (database sessions, authentication)

#### Utility Modules
- **utils/security.py**: Security-related utilities (hashing, risk calculation)
- **utils/logging.py**: Centralized logging configuration
- **utils/notifications.py**: Alert notification system (email, webhook)

### API Endpoints

#### Alert Management
- `POST /api/v1/alerts`: Log new alert/event
- `GET /api/v1/alerts`: Retrieve alerts with filtering and pagination
- `GET /api/v1/alerts/{id}`: Get specific alert details
- `DELETE /api/v1/alerts/{id}`: Delete alert (admin only)
- `GET /api/v1/alerts/summary`: Get alert summary statistics

#### Monitoring Control
- `GET /api/v1/monitoring/status`: Get monitoring service status
- `POST /api/v1/monitoring/start`: Start monitoring service
- `POST /api/v1/monitoring/stop`: Stop monitoring service
- `GET /api/v1/monitoring/config`: Get current monitoring configuration
- `PUT /api/v1/monitoring/config`: Update monitoring configuration

#### System Information
- `GET /api/v1/system/info`: Get system information
- `GET /api/v1/system/processes`: Get current processes
- `GET /api/v1/system/network`: Get network connections
- `GET /api/v1/system/files`: Get monitored files information

#### Configuration
- `GET /api/v1/config`: Get application configuration
- `PUT /api/v1/config`: Update configuration
- `POST /api/v1/config/malware-hashes`: Add malware hash
- `DELETE /api/v1/config/malware-hashes/{hash}`: Remove malware hash

### Database Schema

#### Core Tables
```sql
-- Alerts table (enhanced from existing)
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    extra TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Malware hashes table
CREATE TABLE malware_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    added_by VARCHAR(100),
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- System events table
CREATE TABLE system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User sessions table (for future authentication)
CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Additional Tables for Enhanced Features
```sql
-- Risk thresholds configuration
CREATE TABLE risk_thresholds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category VARCHAR(50) UNIQUE NOT NULL,
    warning_threshold INTEGER NOT NULL,
    critical_threshold INTEGER NOT NULL,
    enabled BOOLEAN DEFAULT TRUE
);

-- Monitoring configuration
CREATE TABLE monitoring_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Data Flow and Integration Points

### Data Flow Diagram
```
[Monitoring Script] --> [FastAPI Backend] --> [SQLite Database]
       ^                       |                       |
       |                       v                       v
[File System Events]     [API Endpoints]        [Persistent Storage]
[Process Events]         [WebSocket Updates]    [Alert History]
[Network Events]         [Scheduled Tasks]      [Configuration]
[Risk Calculations]      [Background Jobs]      [System Metrics]

[React Frontend] <--HTTP/WebSocket--> [FastAPI Backend]
       ^
       |
[User Interactions] --> [State Management] --> [UI Updates]
[Real-time Updates]     [API Calls]           [Dashboard]
[Configuration]         [WebSocket Subscriptions]
```

### Integration Points

#### Backend-Frontend Integration
- **REST API**: Primary communication channel for data retrieval and configuration
- **WebSocket**: Real-time updates for alerts and system status
- **Authentication**: JWT tokens for secure API access

#### Backend-Monitoring Integration
- **Direct Function Calls**: Monitoring modules integrated into FastAPI application
- **Background Tasks**: APScheduler for periodic monitoring execution
- **Event-Driven**: Monitoring events trigger API logging and database updates

#### Database Integration
- **SQLAlchemy ORM**: Object-relational mapping for database operations
- **Connection Pooling**: Efficient database connection management
- **Migrations**: Alembic for schema evolution and versioning

## Deployment Considerations

### Development Environment
- **Local Setup**: Docker Compose for consistent development environment
- **Hot Reload**: FastAPI and Vite for rapid development iteration
- **Database**: Local SQLite instance with migration support

### Production Deployment

#### Containerized Deployment
```yaml
# docker-compose.yml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - DATABASE_URL=sqlite:///./data/sentinel.db
    depends_on:
      - db

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=sentinel
      - POSTGRES_USER=sentinel
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

#### Cloud Deployment Options
- **Backend**: Deploy to AWS ECS, Google Cloud Run, or Azure Container Instances
- **Frontend**: Static hosting on Vercel, Netlify, or AWS S3 + CloudFront
- **Database**: AWS RDS PostgreSQL, Google Cloud SQL, or Azure Database for PostgreSQL
- **Monitoring**: AWS CloudWatch, Google Cloud Monitoring, or Azure Monitor

#### Security Considerations
- **HTTPS**: SSL/TLS encryption for all communications
- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **API Security**: Rate limiting, input validation, and SQL injection prevention
- **Data Protection**: Encryption at rest and in transit

#### Scalability Considerations
- **Horizontal Scaling**: Stateless backend design allows for multiple instances
- **Database Scaling**: Connection pooling and read replicas for high load
- **Caching**: Redis for session storage and API response caching
- **Load Balancing**: Nginx or cloud load balancers for traffic distribution

#### Monitoring and Logging
- **Application Monitoring**: Prometheus metrics and Grafana dashboards
- **Log Aggregation**: Centralized logging with ELK stack or cloud logging services
- **Alerting**: Automated alerts for system issues and security events
- **Performance Monitoring**: APM tools for identifying bottlenecks

This architecture provides a solid foundation for a modern, scalable EDR monitoring dashboard while maintaining compatibility with the existing monitoring logic and extending functionality for future enhancements.