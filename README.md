# CodeWatch - Code Security Service

A FastAPI-based service for code security scanning and analysis.

## Project Description

CodeWatch is a security-focused code analysis service that helps businesses identify and monitor security vulnerabilities, code quality issues, and compliance problems in their source code repositories.

## Features

- **User Management**: Register businesses/organizations with API credentials
- **Code Scanning**: Submit projects for security scanning with different scan modes (quick, standard, deep)
- **API Authentication**: Secure API key and token-based authentication
- **Async Database**: Built on SQLAlchemy with async/await for high performance

## Tech Stack

- **Framework**: FastAPI 0.110+
- **Database**: SQLite with SQLAlchemy async ORM
- **Python**: 3.11+
- **Authentication**: API Key + Business Token
- **Security**: Bcrypt for key hashing

## Project Structure

```
codewatch/
├── app/
│   ├── core/              # Configuration and database setup
│   ├── models/            # SQLAlchemy models
│   ├── schemas/           # Pydantic request/response schemas
│   ├── api/v1/           # API v1 endpoints
│   ├── services/          # Business logic services
│   ├── dependencies/      # FastAPI dependencies (auth, etc.)
│   └── main.py           # Application entry point
├── tests/                 # Test suite
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
└── README.md             # This file
```

## Installation

### Prerequisites
- Python 3.11+
- pip

### Setup

1. Clone the repository:
```bash
cd codewatch
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Running the Application

### Development

```bash
python -m uvicorn app.main:app --reload
```

The application will be available at `http://localhost:8000`

### API Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### User Management

#### Register a New User
```
POST /api/v1/users/register
Content-Type: application/json

{
    "business_id": "my-company-001",
    "business_name": "My Company",
    "api_key": "my-secret-api-key",
    "business_token": "my-business-token"
}

Response: 201 Created
{
    "id": 1,
    "business_id": "my-company-001",
    "business_name": "My Company",
    "is_active": true,
    "created_at": "2025-02-17T10:00:00"
}
```

### Code Scanning

#### Submit a Project for Scanning
```
POST /api/v1/scans/submit
X-API-Key: my-secret-api-key
X-Business-Token: my-business-token
Content-Type: application/json

{
    "project_path": "/home/ubuntu/my-project",
    "scan_mode": "quick"
}

Response: 202 Accepted
{
    "scan_id": "abc123def456...",
    "status": "queued",
    "project_path": "/home/ubuntu/my-project",
    "message": "Scan queued successfully"
}
```

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=app tests/
```

Run specific test file:
```bash
pytest tests/test_users.py
```

## Environment Variables

See `.env.example` for all available configuration options:

- `APP_NAME`: Application name (default: CodeWatch)
- `APP_VERSION`: Application version (default: 0.1.0)
- `DEBUG`: Enable debug mode (default: true)
- `DATABASE_URL`: Database connection URL
- `SECRET_KEY`: Secret key for security operations

## Development Notes

### Adding New Endpoints

1. Create endpoint file in `app/api/v1/endpoints/`
2. Define Pydantic schemas in `app/schemas/`
3. Implement business logic in `app/services/`
4. Include router in `app/api/v1/router.py`
5. Add tests in `tests/`

### Database Migrations

For now, tables are auto-created on startup. For production, consider using Alembic for migrations.

## Security Considerations

- API keys are hashed with bcrypt before storage
- All API endpoints require authentication headers
- Sensitive fields (api_key, business_token) are never returned in responses
- Use strong SECRET_KEY in production
- Enable HTTPS in production deployments

## Future Enhancements

- [ ] Scan result storage and retrieval
- [ ] Scan history and reporting
- [ ] Real code analysis engine integration
- [ ] Webhook notifications for scan completion
- [ ] Admin dashboard
- [ ] Rate limiting
- [ ] Audit logging

## License

[Add your license here]

## Support

For issues and questions, please create an issue in the repository.
