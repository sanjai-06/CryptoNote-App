/**
 * Minimal CryptoNote Server for Testing
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const winston = require('winston');

const app = express();

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Basic security headers
app.use(helmet());

// CORS
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Basic API routes
app.get('/api/test', (req, res) => {
  res.json({ message: 'CryptoNote API is running!' });
});

// Basic auth routes for frontend compatibility
app.post('/api/auth/register', (req, res) => {
  logger.info('Registration attempt:', { username: req.body.username, email: req.body.email });
  res.status(501).json({ 
    error: 'Registration not implemented in minimal server',
    message: 'Please use the full server for authentication features',
    code: 'NOT_IMPLEMENTED'
  });
});

app.post('/api/auth/login', (req, res) => {
  logger.info('Login attempt:', { email: req.body.email });
  res.status(501).json({ 
    error: 'Login not implemented in minimal server',
    message: 'Please use the full server for authentication features',
    code: 'NOT_IMPLEMENTED'
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.json({ message: 'Logout successful (minimal server)' });
});

// Basic password routes
app.get('/api/passwords', (req, res) => {
  res.status(501).json({ 
    error: 'Password management not implemented in minimal server',
    message: 'Please use the full server for password management',
    code: 'NOT_IMPLEMENTED'
  });
});

app.get('/api/categories', (req, res) => {
  res.status(501).json({ 
    error: 'Categories not implemented in minimal server',
    message: 'Please use the full server for category management',
    code: 'NOT_IMPLEMENTED'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    code: 'NOT_FOUND'
  });
});

// Error handler
app.use((error, req, res, next) => {
  logger.error('Server error:', error.message);
  
  res.status(error.status || 500).json({
    error: 'Internal server error',
    code: 'SERVER_ERROR'
  });
});

// Start server
async function startServer() {
  try {
    // Connect to MongoDB if available
    if (process.env.MONGO_URI) {
      try {
        await mongoose.connect(process.env.MONGO_URI);
        logger.info('MongoDB connected successfully');
      } catch (error) {
        logger.warn('MongoDB connection failed, continuing without database:', error.message);
      }
    }

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      logger.info(`🔐 CryptoNote Server (Minimal) running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Health check: http://localhost:${PORT}/health`);
    });

  } catch (error) {
    logger.error('Server startup failed:', error);
    process.exit(1);
  }
}

startServer();
