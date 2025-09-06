# SSO JWT Service

A complete Single Sign-On (SSO) service built with Node.js, Express, JWT tokens, and MySQL database integration.

## Features

- 🔐 **JWT Authentication** - Access and refresh token implementation
- 👤 **User Management** - Complete user CRUD operations with role-based access
- 🛡️ **Security** - Rate limiting, CORS, Helmet security headers, password hashing
- 🗄️ **Database Integration** - MySQL with Sequelize ORM
- 🔄 **SSO Flow** - OAuth2-like authorization code flow
- 📊 **Admin Dashboard** - User statistics and management endpoints
- ✅ **Input Validation** - Comprehensive request validation with Joi

## Database Schema

The service uses your existing MySQL database schema:

### Users Table
```sql
CREATE TABLE Users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    number_of_failed_attempts INT DEFAULT 0,
    password_update_date DATE,
    password_create_date DATE DEFAULT (CURDATE()),
    active BOOLEAN DEFAULT TRUE
);
```

### UserProfile Table
```sql
CREATE TABLE UserProfile (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_userprofile_username FOREIGN KEY (username) REFERENCES Users(username)
);
```

## Installation & Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Configuration**
   Create a `.env` file with your database and JWT configuration:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=your_database_name
   DB_USER=your_username
   DB_PASSWORD=your_password

   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key
   JWT_ACCESS_EXPIRY=1h
   JWT_REFRESH_EXPIRY=7d

   # Server Configuration
   PORT=3000
   NODE_ENV=development

   # Security Configuration
   ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=100
   ```

3. **Start the Server**
   ```bash
   npm start
   ```

## API Endpoints

### Authentication Endpoints

#### POST `/api/auth/login`
Login with email and password
```json
{
  "email": "admin@example.com",
  "password": "admin123"
}
```

#### POST `/api/auth/register`
Register a new user
```json
{
  "email": "user@example.com",
  "password": "password123",
  "username": "newuser",
  "role": "user"
}
```

#### POST `/api/auth/refresh`
Refresh access token using refresh token
```json
{
  "refreshToken": "your-refresh-token"
}
```

#### GET `/api/auth/me`
Get current user information (requires Bearer token)

#### GET `/api/auth/validate`
Validate access token (for other services)

#### POST `/api/auth/logout`
Logout and revoke refresh token

#### POST `/api/auth/logout-all`
Logout from all devices

### User Management Endpoints (Admin Only)

#### GET `/api/users`
Get all users with pagination

#### GET `/api/users/stats`
Get user statistics

#### PUT `/api/users/:id`
Update user information

#### DELETE `/api/users/:id`
Soft delete user

### SSO Endpoints

#### POST `/api/sso/authorize`
Generate authorization code for SSO flow
```json
{
  "clientId": "your-client-id",
  "redirectUri": "http://localhost:3001/callback",
  "responseType": "code",
  "scope": "read write"
}
```

#### POST `/api/sso/token`
Exchange authorization code for tokens
```json
{
  "code": "authorization-code",
  "clientId": "your-client-id",
  "redirectUri": "http://localhost:3001/callback",
  "grantType": "authorization_code"
}
```

### Health Check

#### GET `/health`
Service health check endpoint

## Default Admin User

The service automatically creates a default admin user on startup:
- **Email**: `admin@example.com`
- **Password**: `admin123`
- **Role**: `admin`

## Security Features

- **Password Hashing**: bcrypt with salt rounds
- **Rate Limiting**: Configurable request limits
- **CORS Protection**: Configurable allowed origins
- **Helmet Security**: Security headers
- **Input Validation**: Joi schema validation
- **JWT Security**: Signed tokens with expiration
- **Failed Login Tracking**: Automatic failed attempt counting

## Token Structure

### Access Token
- **Expiry**: 1 hour (configurable)
- **Contains**: userId, email, role, permissions
- **Usage**: API authentication

### Refresh Token
- **Expiry**: 7 days (configurable)
- **Contains**: userId, email, type
- **Usage**: Token refresh only

## Role-Based Access Control

### User Roles
- **admin**: Full access to all endpoints
- **user**: Limited access to user endpoints

### Permissions
- **read**: View data
- **write**: Create/update data
- **delete**: Delete data
- **admin**: Administrative functions

## Testing

Run the test suite to verify functionality:
```bash
node test-sso.js
```

The test covers:
- Health check
- User login
- Protected route access
- Admin functionality
- Token management

## Production Considerations

1. **Database**: Use connection pooling and proper indexing
2. **Token Storage**: Consider Redis for refresh token storage
3. **Logging**: Implement comprehensive logging
4. **Monitoring**: Add health checks and metrics
5. **SSL/TLS**: Use HTTPS in production
6. **Environment**: Set NODE_ENV=production
7. **Secrets**: Use proper secret management

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │────│   SSO Service   │────│   MySQL DB      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                       ┌─────────────────┐
                       │   Other Apps    │
                       └─────────────────┘
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details
