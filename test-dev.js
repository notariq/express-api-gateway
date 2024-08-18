require("dotenv").config(); // Load environment variables
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { createProxyMiddleware } = require("http-proxy-middleware");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require('./db/db')

const User = db.User;

const app = express();

// Middleware setup
app.use(cors()); // Enable CORS
app.use(helmet()); // Add security headers
app.use(morgan("combined")); // Log HTTP requests
app.use(express.json()); // Parse JSON bodies
app.disable("x-powered-by"); // Hide Express server

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key"; // Use environment variable

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res.status(401).json({
      code: 401,
      status: "Error",
      message: "Unauthorized: No token provided.",
      data: null,
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        code: 403,
        status: "Error",
        message: "Forbidden: Invalid token.",
        data: null,
      });
    }

    req.user = user;
    next();
  });
}

// User registration endpoint
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the user already exists (case insensitive)
    const existingUser = await User.findOne({ where: { name: { $iLike: name } } });
    if (existingUser) {
      return res.status(400).json({
        code: 400,
        status: "Error",
        message: "Username already exists.",
        data: null,
      });
    }

    const existingEmail = await User.findOne({ where: { email } });
    if (existingEmail) {
      return res.status(400).json({
        code: 400,
        status: "Error",
        message: "Email already exists.",
        data: null,
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the new user
    await User.create({ name, email, password: hashedPassword });

    res.status(201).json({
      code: 201,
      status: "Success",
      message: "User registered successfully.",
      data: null,
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({
      code: 500,
      status: "Error",
      message: "Internal server error.",
      data: null,
    });
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  const { name, password } = req.body;

  try {
    // Find the user
    const user = await User.findOne({ where: { name } });
    if (!user) {
      return res.status(400).json({
        code: 400,
        status: "Error",
        message: "Invalid username or password.",
        data: null,
      });
    }

    // Check the password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({
        code: 400,
        status: "Error",
        message: "Invalid username or password.",
        data: null,
      });
    }

    // Generate a JWT
    const token = jwt.sign({ name: user.name }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({
      code: 200,
      status: "Success",
      message: "Logged in successfully.",
      data: { token },
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({
      code: 500,
      status: "Error",
      message: "Internal server error.",
      data: null,
    });
  }
});

// Define routes and corresponding microservices
const services = [
  {
    route: "/users",
    target: "http://localhost:6000/api/users",
  },
  {
    route: "/song",
    target: "http://localhost:4000/api/music",
  },
  {
    route: "/playlist",
    target: "http://localhost:5000/api/playlist",
  },
  // Add more services as needed either deployed or locally.
];

// Rate limit constants
const rateLimit = 20; // Max requests per minute
const interval = 60 * 1000; // Time window in milliseconds (1 minute)

// Object to store request counts for each IP address
const requestCounts = {};

// Reset request count for each IP address every 'interval' milliseconds
setInterval(() => {
  Object.keys(requestCounts).forEach((ip) => {
    requestCounts[ip] = 0; // Reset request count for each IP address
  });
}, interval);

// Middleware function for rate limiting and timeout handling
function rateLimitAndTimeout(req, res, next) {
  const ip = req.ip; // Get client IP address

  // Update request count for the current IP
  requestCounts[ip] = (requestCounts[ip] || 0) + 1;

  // Check if request count exceeds the rate limit
  if (requestCounts[ip] > rateLimit) {
    // Respond with a 429 Too Many Requests status code
    return res.status(429).json({
      code: 429,
      status: "Error",
      message: "Rate limit exceeded.",
      data: null,
    });
  }

  // Set timeout for each request (example: 15 seconds)
  req.setTimeout(15000, () => {
    // Handle timeout error
    res.status(504).json({
      code: 504,
      status: "Error",
      message: "Gateway timeout.",
      data: null,
    });
    req.abort(); // Abort the request
  });

  next(); // Continue to the next middleware
}

// Apply the rate limit and timeout middleware to the proxy
app.use(rateLimitAndTimeout);

// Set up proxy middleware for each microservice
services.forEach(({ route, target }) => {
  // Proxy options
  const proxyOptions = {
    target,
    changeOrigin: true,
    pathRewrite: {
      [`^${route}`]: "",
    },
  };

  // Apply authentication, rate limiting, and timeout middleware before proxying
  app.use(route, authenticateToken, rateLimitAndTimeout, createProxyMiddleware(proxyOptions));
});

// Handler for route-not-found
app.use((_req, res) => {
  res.status(404).json({
    code: 404,
    status: "Error",
    message: "Route not found.",
    data: null,
  });
});

// Define port for Express server
const PORT = process.env.PORT || 8080;

// Start Express server
db.sequelize.sync()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Error starting server:', err);
  });
