#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colorful status messages
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

# Check required tools
check_command "node"
check_command "npm"
check_command "go"
check_command "git"

# Get project name from user
read -p "Enter your project name (lowercase, no spaces): " PROJECT_NAME

# Validate project name
if [[ ! $PROJECT_NAME =~ ^[a-z0-9-]+$ ]]; then
    print_error "Invalid project name. Use only lowercase letters, numbers, and hyphens."
    exit 1
fi

# Create project directory
print_status "Creating project directory..."
mkdir "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Initialize git repository
print_status "Initializing git repository..."
git init

# Create frontend
print_status "Setting up frontend..."
npx create-react-app frontend --template typescript

cd frontend

# Install frontend dependencies
print_status "Installing frontend dependencies..."
npm install \
    @auth0/auth0-react \
    @stripe/stripe-js \
    axios \
    react-router-dom \
    @types/node \
    @types/react \
    @types/react-dom \
    tailwindcss \
    postcss \
    autoprefixer

# Initialize Tailwind CSS
npx tailwindcss init -p

# Create frontend environment file
cat > .env.example << EOL
REACT_APP_AUTH0_DOMAIN=your-auth0-domain
REACT_APP_AUTH0_CLIENT_ID=your-auth0-client-id
REACT_APP_AUTH0_AUDIENCE=your-auth0-audience
REACT_APP_STRIPE_PUBLIC_KEY=your-stripe-public-key
REACT_APP_API_URL=http://localhost:8080
EOL

cp .env.example .env

# Setup frontend directory structure
print_status "Creating frontend directory structure..."
cd src
mkdir -p {components/{auth,billing,layout},config,hooks,pages,services,types}

# Create frontend template files
cat > config/auth0Config.ts << 'EOL'
export const auth0Config = {
  domain: process.env.REACT_APP_AUTH0_DOMAIN!,
  clientId: process.env.REACT_APP_AUTH0_CLIENT_ID!,
  audience: process.env.REACT_APP_AUTH0_AUDIENCE!,
  redirectUri: window.location.origin,
};
EOL

cat > components/auth/AuthProvider.tsx << 'EOL'
import { Auth0Provider } from '@auth0/auth0-react';
import { auth0Config } from '../../config/auth0Config';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <Auth0Provider
      domain={auth0Config.domain}
      clientId={auth0Config.clientId}
      redirectUri={auth0Config.redirectUri}
      audience={auth0Config.audience}
    >
      {children}
    </Auth0Provider>
  );
};
EOL

cat > hooks/useAuth.ts << 'EOL'
import { useAuth0 } from '@auth0/auth0-react';

export const useAuth = () => {
  const {
    isAuthenticated,
    loginWithRedirect,
    logout,
    user,
    getAccessTokenSilently,
  } = useAuth0();

  const getToken = async () => {
    try {
      return await getAccessTokenSilently();
    } catch (error) {
      console.error('Error getting token:', error);
      return null;
    }
  };

  return {
    isAuthenticated,
    login: loginWithRedirect,
    logout,
    user,
    getToken,
  };
};
EOL

cat > services/api.ts << 'EOL'
import axios from 'axios';
import { useAuth } from '../hooks/useAuth';

const API_URL = process.env.REACT_APP_API_URL;

const api = axios.create({
  baseURL: API_URL,
});

api.interceptors.request.use(async (config) => {
  const { getToken } = useAuth();
  const token = await getToken();
  
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  
  return config;
});

export default api;
EOL

cat > services/stripe.ts << 'EOL'
import { loadStripe } from '@stripe/stripe-js';
import api from './api';

const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLIC_KEY!);

export const createCheckoutSession = async (priceId: string) => {
  try {
    const { data } = await api.post('/create-checkout-session', { priceId });
    const stripe = await stripePromise;
    await stripe?.redirectToCheckout({ sessionId: data.sessionId });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    throw error;
  }
};

export const redirectToBillingPortal = async () => {
  try {
    const { data } = await api.post('/create-portal-session');
    window.location.href = data.url;
  } catch (error) {
    console.error('Error redirecting to billing portal:', error);
    throw error;
  }
};
EOL

cd ../..

# Create backend
print_status "Setting up backend..."
mkdir backend
cd backend

# Initialize Go module
go mod init "${PROJECT_NAME}-backend"

# Install backend dependencies
print_status "Installing backend dependencies..."
go get -u github.com/gin-gonic/gin
go get -u github.com/joho/godotenv
go get -u github.com/stripe/stripe-go/v74
go get -u github.com/auth0/go-jwt-middleware/v2

# Create backend directory structure
print_status "Creating backend directory structure..."
mkdir -p {cmd/api,internal/{auth,config,handlers,models,services},pkg/utils}

# Create backend template files
cat > cmd/api/main.go << 'EOL'
package main

import (
    "log"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
)

func main() {
    if err := godotenv.Load(); err != nil {
        log.Printf("Error loading .env file: %v", err)
    }

    r := gin.Default()

    // Middleware
    r.Use(auth.AuthMiddleware())

    // Routes
    api := r.Group("/api")
    {
        // User routes
        api.GET("/user", handlers.GetUser)
        api.PUT("/user", handlers.UpdateUser)

        // Billing routes
        api.POST("/create-checkout-session", handlers.CreateCheckoutSession)
        api.POST("/create-portal-session", handlers.CreatePortalSession)
        api.POST("/webhook", handlers.HandleStripeWebhook)
    }

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    if err := r.Run(":" + port); err != nil {
        log.Fatal("Error starting server:", err)
    }
}
EOL

cat > internal/auth/middleware.go << 'EOL'
package auth

import (
    "errors"
    "net/http"
    "os"
    "strings"

    "github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractToken(c)
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
            c.Abort()
            return
        }

        valid, err := validateToken(token)
        if err != nil || !valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Next()
    }
}

func extractToken(c *gin.Context) string {
    bearerToken := c.GetHeader("Authorization")
    if len(strings.Split(bearerToken, " ")) == 2 {
        return strings.Split(bearerToken, " ")[1]
    }
    return ""
}

func validateToken(token string) (bool, error) {
    // Implement Auth0 token validation logic here
    return true, nil
}
EOL

cat > internal/handlers/billing.go << 'EOL'
package handlers

import (
    "net/http"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/stripe/stripe-go/v74"
    "github.com/stripe/stripe-go/v74/checkout/session"
    "github.com/stripe/stripe-go/v74/billingportal/session"
)

func CreateCheckoutSession(c *gin.Context) {
    var req struct {
        PriceID string `json:"priceId"`
    }

    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    params := &stripe.CheckoutSessionParams{
        SuccessURL: stripe.String(os.Getenv("STRIPE_SUCCESS_URL")),
        CancelURL:  stripe.String(os.Getenv("STRIPE_CANCEL_URL")),
        Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
        LineItems: []*stripe.CheckoutSessionLineItemParams{
            {
                Price:    stripe.String(req.PriceID),
                Quantity: stripe.Int64(1),
            },
        },
    }

    session, err := session.New(params)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"sessionId": session.ID})
}

func CreatePortalSession(c *gin.Context) {
    // Get customer ID from authenticated user
    customerID := "cus_xxx" // Replace with actual customer ID lookup

    params := &stripe.BillingPortalSessionParams{
        Customer:    stripe.String(customerID),
        ReturnURL:  stripe.String(os.Getenv("STRIPE_PORTAL_RETURN_URL")),
    }

    session, err := portalsession.New(params)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"url": session.URL})
}
EOL

# Create backend environment file
cat > .env.example << EOL
PORT=8080
AUTH0_DOMAIN=your-auth0-domain
AUTH0_AUDIENCE=your-auth0-audience
STRIPE_SECRET_KEY=your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=your-stripe-webhook-secret
STRIPE_SUCCESS_URL=http://localhost:3000/success
STRIPE_CANCEL_URL=http://localhost:3000/cancel
STRIPE_PORTAL_RETURN_URL=http://localhost:3000/account
EOL

cp .env.example .env

cd ..

# Create docker-compose file
cat > docker-compose.yml << EOL
version: '3.8'
services:
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
    volumes:
      - ./frontend:/app
      - /app/node_modules

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - GIN_MODE=debug
    volumes:
      - ./backend:/app
EOL

# Create frontend Dockerfile
cat > frontend/Dockerfile << EOL
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000
CMD ["npm", "start"]
EOL

# Create backend Dockerfile
cat > backend/Dockerfile << EOL
FROM golang:1.20-alpine

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . .

RUN go build -o main ./cmd/api

EXPOSE 8080
CMD ["./main"]
EOL

# Create .gitignore
cat > .gitignore << EOL
# Dependencies
node_modules
.pnp
.pnp.js

# Testing
coverage

# Production
build
dist

# Environment files
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Editor directories
.idea
.vscode
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db
EOL

# Initialize git repository
git add .
git commit -m "Initial commit: Project setup"

print_success "Project setup complete! 🚀"
print_success "Your project structure has been created at: $(pwd)/$PROJECT_NAME"
echo
print_status "Next steps:"
echo "1. Review and update the environment files in both frontend and backend directories"
echo "2. cd $PROJECT_NAME"
echo "3. Start the development servers:"
echo "   - Frontend: cd frontend && npm start"
echo "   - Backend: cd backend && go run cmd/api/main.go"
echo "   - Or use Docker: docker-compose up"
