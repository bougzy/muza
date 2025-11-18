// ================== IMPORTS ==================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const fs = require('fs');
const cors = require('cors');

// ================== APP SETUP ==================
const app = express();

// ================== CORS CONFIGURATION ==================
// Enhanced CORS configuration for production
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'https://yourfrontenddomain.com',
      'https://muzaf.vercel.app',
      'https://worldcurencytrade.vercel.app',
    ];

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      if (process.env.NODE_ENV === 'production') {
        console.log('Blocked CORS request from origin:', origin);
        callback(new Error('Not allowed by CORS'));
      } else {
        callback(null, true);
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers',
    'Admin-Username',
    'Admin-Password'
  ],
  exposedHeaders: [
    'Content-Range',
    'X-Content-Range',
    'Content-Disposition'
  ],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Security headers
app.use((req, res, next) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ================== MIDDLEWARE ==================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestIp.mw());

const server = http.createServer(app);

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// ================== DB CONNECTION ==================
mongoose.connect(process.env.MONGO_URI || "mongodb+srv://muza:muza@muza.bgig3zj.mongodb.net/muza", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ================== ENHANCED LOCATION UTILITIES ==================

const validateAndCleanIP = (ip) => {
  if (!ip) return '0.0.0.0';
  if (ip === '::1') return '127.0.0.1';
  if (ip.includes(':')) {
    const parts = ip.split(':');
    const possibleIp = parts[parts.length - 1];
    if (possibleIp && possibleIp !== '') return possibleIp;
  }
  return ip;
};

const getUserLocation = (ip) => {
  const cleanIp = validateAndCleanIP(ip);
  
  if (cleanIp === '127.0.0.1') {
    return {
      country: 'US',
      countryCode: 'US',
      region: 'California',
      regionName: 'California',
      city: 'San Francisco',
      zip: '94107',
      lat: 37.7749,
      lon: -122.4194,
      timezone: 'America/Los_Angeles',
      isp: 'Local Development',
      org: 'Local Network',
      as: 'AS0 Local',
      query: cleanIp,
      source: 'fallback'
    };
  }

  try {
    const geo = geoip.lookup(cleanIp);
    if (geo) {
      return {
        country: geo.country,
        countryCode: geo.country,
        region: geo.region,
        regionName: geo.region,
        city: geo.city,
        zip: '',
        lat: geo.ll[0],
        lon: geo.ll[1],
        timezone: geo.timezone,
        isp: 'Unknown',
        org: 'Unknown',
        as: 'Unknown',
        query: cleanIp,
        source: 'geoip-lite'
      };
    }
  } catch (error) {
    console.error('❌ Error in location lookup:', error);
  }

  return {
    country: 'Unknown',
    countryCode: 'XX',
    region: 'Unknown',
    regionName: 'Unknown',
    city: 'Unknown',
    zip: '',
    lat: 0,
    lon: 0,
    timezone: 'UTC',
    isp: 'Unknown',
    org: 'Unknown',
    as: 'Unknown',
    query: cleanIp,
    source: 'fallback'
  };
};

// ================== MODELS ==================

// Enhanced User Schema with Better Location Tracking
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, select: false, required: true },
  confirmPassword: { type: String, select: false },
  secretQuestion: { type: String, required: true },
  secretAnswer: { type: String, select: false, required: true },
  bitcoinAccount: { type: String },
  tetherTRC20Account: { type: String },
  ipAddress: { type: String },
  location: {
    country: String,
    countryCode: String,
    region: String,
    regionName: String,
    city: String,
    zip: String,
    timezone: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    },
    isp: String,
    organization: String,
    asNumber: String,
    source: String,
    queryIp: String,
    lastUpdated: Date
  },
  lastLogin: { type: Date },
  loginHistory: [{
    ip: String,
    location: Object,
    timestamp: { type: Date, default: Date.now },
    event: String
  }],
  role: { type: String, default: "user" },
  walletBalance: { type: Number, default: 0 },
  depositBalance: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  referralCode: { type: String, unique: true },
  agreedToTerms: { type: Boolean, default: false },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  isBlocked: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
}, { timestamps: true });

userSchema.pre("save", async function(next) {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    if (this.confirmPassword) {
      this.confirmPassword = await bcrypt.hash(this.confirmPassword, salt);
    }
  }

  if (this.isModified("secretAnswer")) {
    const salt = await bcrypt.genSalt(10);
    this.secretAnswer = await bcrypt.hash(this.secretAnswer, salt);
  }

  if (!this.referralCode) {
    let code, exists = true;
    while (exists) {
      code = crypto.randomBytes(3).toString("hex");
      const user = await User.findOne({ referralCode: code.toUpperCase() });
      if (!user) exists = false;
    }
    this.referralCode = code.toUpperCase();
  }
  next();
});

userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.matchSecretAnswer = async function(enteredAnswer) {
  return await bcrypt.compare(enteredAnswer, this.secretAnswer);
};

const User = mongoose.model("User", userSchema);

// Enhanced Admin Schema with username
const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true, select: false },
  name: { type: String, required: true },
  role: { type: String, default: "admin" }
}, { timestamps: true });

adminSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

adminSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const Admin = mongoose.model("Admin", adminSchema);

// Earnings Breakdown Schema
const earningsBreakdownSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  period: { type: String, enum: ["daily", "weekly", "monthly"], required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  profit: { type: Number, default: 0 },
  deposit: { type: Number, default: 0 },
  investment: { type: Number, default: 0 },
  totalEarnings: { type: Number, default: 0 },
  notes: String,
  generatedBy: { type: String, default: "admin" },
  isFinalized: { type: Boolean, default: false }
}, { timestamps: true });

const EarningsBreakdown = mongoose.model("EarningsBreakdown", earningsBreakdownSchema);

// Custom Transaction Report Schema
const transactionReportSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  description: String,
  transactions: [{
    date: Date,
    type: String,
    amount: Number,
    description: String,
    balance: Number
  }],
  summary: {
    totalDeposits: Number,
    totalWithdrawals: Number,
    totalInvestments: Number,
    totalProfits: Number,
    netBalance: Number
  },
  generatedBy: { type: String, default: "admin" },
  isSent: { type: Boolean, default: false },
  sentAt: Date
}, { timestamps: true });

const TransactionReport = mongoose.model("TransactionReport", transactionReportSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, enum: ["deposit", "withdrawal", "investment", "profit", "admin_adjustment"], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  adminNote: String,
  proof: String,
  processed: { type: Boolean, default: false },
  investmentPlan: String,
  walletAddress: String,
}, { timestamps: true });

const Transaction = mongoose.model("Transaction", transactionSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  transaction: { type: mongoose.Schema.Types.ObjectId, ref: "Transaction", required: true },
  planName: { type: String, required: true },
  amount: { type: Number, required: true },
  profitRate: { type: Number, required: true },
  expectedProfit: { type: Number, required: true },
  status: { type: String, enum: ["active", "completed", "cancelled"], default: "active" },
  startDate: { type: Date, default: Date.now },
  endDate: Date,
  profits: [{
    amount: Number,
    date: { type: Date, default: Date.now },
    note: String
  }],
  totalProfitEarned: { type: Number, default: 0 }
}, { timestamps: true });

const Investment = mongoose.model("Investment", investmentSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: { type: String, required: true },
  content: { type: String, required: true },
  type: { type: String, default: "info" },
  isRead: { type: Boolean, default: false },
  relatedId: mongoose.Schema.Types.ObjectId,
  relatedType: String
}, { timestamps: true });

const Notification = mongoose.model("Notification", notificationSchema);

// Profit Schema
const profitSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true },
  note: String,
  investmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Investment" },
}, { timestamps: true });

const Profit = mongoose.model("Profit", profitSchema);

// ================== MIDDLEWARE ==================

// Enhanced file upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || 
        file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDF files are allowed'), false);
    }
  }
});

// Enhanced authentication middleware
const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Access denied. No token provided." 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecretjwtkey");
    const user = await User.findById(decoded.id).select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User not found." 
      });
    }
    
    if (user.isBlocked) {
      return res.status(403).json({ 
        success: false,
        message: "Account has been blocked. Please contact support." 
      });
    }
    
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token." 
      });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: "Token expired." 
      });
    }
    res.status(500).json({ 
      success: false,
      message: "Server error during authentication." 
    });
  }
};

// ENHANCED ADMIN AUTHENTICATION MIDDLEWARE
const adminAuth = async (req, res, next) => {
  try {
    const username = req.headers["admin-username"];
    const password = req.headers["admin-password"];
    
    if (!username || !password) {
      return res.status(401).json({ 
        success: false,
        message: "Admin credentials required" 
      });
    }

    // Check database for admin users first
    const admin = await Admin.findOne({ 
      $or: [
        { username: username },
        { email: username }
      ]
    }).select('+password');
    
    if (admin && await admin.matchPassword(password)) {
      req.admin = {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        name: admin.name,
        role: admin.role
      };
      return next();
    }

    // Fallback to hardcoded credentials
    const HARDCODED_CREDENTIALS = {
      username: "admin",
      password: "admin123"
    };
    
    if (username === HARDCODED_CREDENTIALS.username && password === HARDCODED_CREDENTIALS.password) {
      req.admin = {
        username: HARDCODED_CREDENTIALS.username,
        email: "admin@galaxydigital.com",
        name: "Super Administrator",
        role: "super_admin"
      };
      return next();
    }
    
    res.status(403).json({ 
      success: false,
      message: "Invalid admin credentials" 
    });
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(500).json({ 
      success: false,
      message: "Admin authentication error" 
    });
  }
};

// Enhanced user location update middleware
const updateUserLocation = async (req, res, next) => {
  if (req.user) {
    try {
      const rawIp = req.clientIp;
      const cleanedIp = validateAndCleanIP(rawIp);
      const locationData = getUserLocation(cleanedIp);

      if (locationData.country && locationData.country !== 'Unknown') {
        await User.findByIdAndUpdate(req.user._id, {
          $set: {
            ipAddress: cleanedIp,
            lastLogin: new Date(),
            'location.country': locationData.country,
            'location.city': locationData.city,
            'location.coordinates.latitude': locationData.lat,
            'location.coordinates.longitude': locationData.lon,
            'location.timezone': locationData.timezone,
            'location.lastUpdated': new Date()
          },
          $push: {
            loginHistory: {
              ip: cleanedIp,
              location: locationData,
              timestamp: new Date(),
              event: 'login'
            }
          }
        });
      }
    } catch (error) {
      console.error('Error updating user location:', error);
    }
  }
  next();
};

// ================== UTILS ==================
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET || "supersecretjwtkey", { expiresIn: "7d" });
};

// Enhanced WebSocket system
const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  perMessageDeflate: false,
  verifyClient: (info, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173', 
      'https://yourfrontenddomain.com',
      'https://www.yourfrontenddomain.com',
    ];
    
    const origin = info.origin || info.req.headers.origin;
    
    if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
      callback(true);
    } else {
      console.log('WebSocket CORS blocked:', origin);
      callback(false, 401, 'Unauthorized');
    }
  }
});

const clients = new Map();

wss.on('connection', (ws, req) => {
  console.log('🔌 New WebSocket connection attempt');
  
  const authTimeout = setTimeout(() => {
    if (!ws.authenticated) {
      ws.send(JSON.stringify({
        type: 'ERROR',
        message: 'Authentication timeout'
      }));
      ws.close();
    }
  }, 5000);

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);
      
      if (message.type === 'AUTH' && message.token) {
        clearTimeout(authTimeout);
        
        try {
          const decoded = jwt.verify(message.token, process.env.JWT_SECRET || "supersecretjwtkey");
          const userId = decoded.id;
          
          const user = await User.findById(userId);
          if (!user) {
            ws.send(JSON.stringify({
              type: 'ERROR',
              message: 'User not found'
            }));
            return ws.close();
          }
          
          if (user.isBlocked) {
            ws.send(JSON.stringify({
              type: 'ERROR',
              message: 'Account blocked'
            }));
            return ws.close();
          }
          
          clients.set(userId.toString(), ws);
          ws.userId = userId.toString();
          ws.authenticated = true;
          
          ws.send(JSON.stringify({
            type: 'CONNECTED',
            user: {
              id: user._id,
              username: user.username,
              walletBalance: user.walletBalance,
              depositBalance: user.depositBalance
            },
            message: 'WebSocket connected successfully'
          }));
          
          console.log(`✅ User ${userId} connected via WebSocket`);
          
        } catch (authError) {
          ws.send(JSON.stringify({
            type: 'ERROR',
            message: 'Invalid authentication'
          }));
          ws.close();
        }
      }
    } catch (parseError) {
      ws.send(JSON.stringify({
        type: 'ERROR',
        message: 'Invalid message format'
      }));
    }
  });
  
  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (ws.userId) {
      clients.delete(ws.userId);
      console.log(`❌ User ${ws.userId} disconnected from WebSocket`);
    }
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    clearTimeout(authTimeout);
  });
});

function sendUserUpdate(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      clients.delete(userId);
    }
  }
}

// Enhanced notification system
const sendNotification = async (userId, title, content, type = "info", relatedId = null, relatedType = null) => {
  try {
    const notif = new Notification({ 
      user: userId, 
      title, 
      content, 
      type,
      relatedId,
      relatedType
    });
    await notif.save();
    
    sendUserUpdate(userId.toString(), {
      type: 'NEW_NOTIFICATION',
      notification: notif,
      message: 'You have a new notification'
    });
    
    return notif;
  } catch (error) {
    console.error("Error sending notification:", error);
    return null;
  }
};

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER || 'your_email@gmail.com',
    pass: process.env.SMTP_PASS || 'your_password'
  }
});

// ================== HEALTH CHECK ==================
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is running healthy",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ================== AUTH ROUTES ==================

// Enhanced Registration with Auto-Login
app.post("/api/register", async (req, res) => {
  try {
    const {
      username, name, email, password, confirmPassword,
      bitcoinAccount, tetherTRC20Account, secretQuestion,
      secretAnswer, agreedToTerms, referralCode
    } = req.body;

    // Validation
    if (!username || !name || !email || !password || !confirmPassword || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ 
        success: false,
        message: "All required fields must be provided" 
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ 
        success: false,
        message: "Passwords do not match" 
      });
    }

    if (!agreedToTerms) {
      return res.status(400).json({ 
        success: false,
        message: "You must agree to the terms and conditions" 
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: existingUser.email === email ? "Email already registered" : "Username already taken"
      });
    }

    // Create user
    const user = await User.create({
      username: username.toLowerCase(),
      name,
      email: email.toLowerCase(),
      password,
      secretQuestion,
      secretAnswer,
      bitcoinAccount,
      tetherTRC20Account,
      agreedToTerms: true,
      ipAddress: req.clientIp
    });

    // Generate token for auto-login
    const token = generateToken(user._id, user.role);

    // Get user without sensitive data
    const userResponse = await User.findById(user._id).select("-password -secretAnswer");

    res.status(201).json({
      success: true,
      data: {
        user: userResponse,
        token: token
      },
      message: "Registration successful! You are now logged in."
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        success: false,
        message: "User already exists with this email or username" 
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: "Registration failed. Please try again." 
    });
  }
});

// Enhanced Login with Same Data Access
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    // Find user with password field included
    const user = await User.findOne({ email: email.toLowerCase() }).select("+password");
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Check password
    const isPasswordMatch = await user.matchPassword(password);
    if (!isPasswordMatch) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    if (user.isBlocked) {
      return res.status(403).json({ 
        success: false,
        message: "Account blocked. Please contact support." 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id, user.role);

    // Get user without sensitive data
    const userResponse = await User.findById(user._id).select("-password -secretAnswer");

    res.json({
      success: true,
      data: {
        user: userResponse,
        token: token
      },
      message: "Login successful"
    });

  } catch (error) { 
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      message: "Login failed. Please try again." 
    }); 
  }
});

// Get current user profile
app.get("/api/me", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password -secretAnswer");
    
    res.json({
      success: true,
      data: {
        user: user
      },
      message: "User profile retrieved successfully"
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      success: false,
      message: "Failed to fetch user data" 
    });
  }
});

// ================== ADMIN MANAGEMENT ROUTES ==================

// Get all admins
app.get("/api/admin/admins", adminAuth, async (req, res) => {
  try {
    const admins = await Admin.find({}).select('-password').sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: {
        admins: admins,
        total: admins.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Create new admin
app.post("/api/admin/admins", adminAuth, async (req, res) => {
  try {
    const { username, email, password, name, role = "admin" } = req.body;
    
    if (!username || !email || !password || !name) {
      return res.status(400).json({ 
        success: false,
        message: "All fields are required" 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: "Password must be at least 6 characters long" 
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({
      $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }]
    });
    
    if (existingAdmin) {
      return res.status(400).json({ 
        success: false,
        message: "Admin with this email or username already exists" 
      });
    }

    // Create new admin
    const admin = await Admin.create({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: password,
      name: name,
      role: role
    });

    const adminResponse = await Admin.findById(admin._id).select('-password');

    res.status(201).json({
      success: true,
      message: "Admin created successfully",
      data: { admin: adminResponse }
    });
  } catch (error) {
    console.error('Create admin error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        success: false,
        message: "Admin with this email or username already exists" 
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: "Failed to create admin" 
    });
  }
});

// Change admin password
app.put("/api/admin/admins/:adminId/password", adminAuth, async (req, res) => {
  try {
    const { adminId } = req.params;
    const { newPassword, currentPassword } = req.body;
    
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: "New password must be at least 6 characters long" 
      });
    }

    const admin = await Admin.findById(adminId).select('+password');
    
    if (!admin) {
      return res.status(404).json({ 
        success: false,
        message: "Admin not found" 
      });
    }

    // If changing own password, verify current password
    if (req.admin.id && req.admin.id.toString() === adminId) {
      if (!currentPassword) {
        return res.status(400).json({ 
          success: false,
          message: "Current password is required to change your own password" 
        });
      }
      
      const isCurrentPasswordValid = await admin.matchPassword(currentPassword);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({ 
          success: false,
          message: "Current password is incorrect" 
        });
      }
    }

    admin.password = newPassword;
    await admin.save();

    res.json({
      success: true,
      message: "Password updated successfully"
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ 
      success: false,
      message: "Failed to change password" 
    });
  }
});

// Delete admin
app.delete("/api/admin/admins/:adminId", adminAuth, async (req, res) => {
  try {
    const { adminId } = req.params;
    
    const admin = await Admin.findById(adminId);

    if (!admin) {
      return res.status(404).json({ 
        success: false,
        message: "Admin not found" 
      });
    }

    // Prevent deletion of your own account
    if (req.admin.id && req.admin.id.toString() === adminId) {
      return res.status(400).json({ 
        success: false,
        message: "Cannot delete your own account" 
      });
    }

    await Admin.findByIdAndDelete(adminId);

    res.json({
      success: true,
      message: "Admin deleted successfully"
    });
  } catch (error) {
    console.error('Delete admin error:', error);
    res.status(500).json({ 
      success: false,
      message: "Failed to delete admin" 
    });
  }
});

// ================== ADMIN DASHBOARD ROUTES ==================

app.get("/api/admin/dashboard-stats", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: "deposit", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: "withdrawal", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    
    const totalInvestments = await Transaction.aggregate([
      { $match: { type: "investment", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    
    const pendingDeposits = await Transaction.countDocuments({ 
      type: "deposit", 
      status: "pending" 
    });
    
    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: "withdrawal", 
      status: "pending" 
    });
    
    const pendingInvestments = await Transaction.countDocuments({ 
      type: "investment", 
      status: "pending" 
    });

    const recentRegistrations = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select("username email location ipAddress createdAt");

    // Online users count (users with active WebSocket connections)
    const onlineUsers = Array.from(clients.keys()).length;

    res.json({
      success: true,
      data: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        totalInvestments: totalInvestments[0]?.total || 0,
        pendingTransactions: {
          deposits: pendingDeposits,
          withdrawals: pendingWithdrawals,
          investments: pendingInvestments,
          total: pendingDeposits + pendingWithdrawals + pendingInvestments
        },
        recentRegistrations,
        onlineUsers,
        systemHealth: {
          database: 'connected',
          websocket: 'active',
          uptime: process.uptime()
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Admin Transactions with Location Data
app.get("/api/admin/transactions", adminAuth, async (req, res) => {
  try {
    const { type, status, page = 1, limit = 50 } = req.query;
    
    const filter = {};
    if (type && type !== 'all') filter.type = type;
    if (status && status !== 'all') filter.status = status;
    
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find(filter)
      .populate('user', 'username email location ipAddress')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        transactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get Pending Deposits Specifically
app.get("/api/admin/pending-deposits", adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Transaction.find({ 
      type: "deposit", 
      status: "pending" 
    })
    .populate('user', 'username email location ipAddress createdAt')
    .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      message: "Pending deposits retrieved successfully",
      data: {
        deposits: pendingDeposits,
        count: pendingDeposits.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Deposit Approval with Real-time Updates
app.put("/api/admin/deposit/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "deposit") {
      return res.status(404).json({ 
        success: false,
        message: "Deposit transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Deposit already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    const oldWalletBalance = user.walletBalance;
    const oldDepositBalance = user.depositBalance;

    // Add to both wallet and deposit balance
    user.walletBalance += transaction.amount;
    user.depositBalance += transaction.amount;
    await user.save();

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Deposit Approved ✅",
      `Your deposit of $${transaction.amount} has been approved and added to your balances.`,
      "deposit",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'DEPOSIT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      transaction: transaction,
      amount: transaction.amount,
      message: `Deposit of $${transaction.amount} has been approved and added to your balances`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Deposit approved successfully", 
      data: { 
        transaction: transaction,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          increase: transaction.amount
        },
        userLocation: user.location
      }
    });
  } catch (error) { 
    console.error('Deposit approval error:', error);
    res.status(500).json({ 
      success: false,
      message: "Deposit approval failed" 
    }); 
  }
});

// Enhanced Admin User Management
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = search ? {
      $or: [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ]
    } : {};
    
    const users = await User.find(filter)
      .select("-password -secretAnswer -confirmPassword")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ================== INVESTMENT APPROVAL ROUTES ==================

// Get pending investments for admin
app.get("/api/admin/pending-investments", adminAuth, async (req, res) => {
  try {
    const pendingInvestments = await Transaction.find({ 
      type: "investment", 
      status: "pending" 
    })
    .populate('user', 'username email location ipAddress createdAt')
    .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      message: "Pending investments retrieved successfully",
      data: {
        investments: pendingInvestments,
        count: pendingInvestments.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Approve investment
app.put("/api/admin/investment/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Investment already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    
    if (user.depositBalance < transaction.amount) {
      return res.status(400).json({ 
        success: false,
        message: "User has insufficient deposit balance for this investment" 
      });
    }

    // Deduct from deposit balance and add to total invested
    user.depositBalance -= transaction.amount;
    user.totalInvested += transaction.amount;
    await user.save();

    // Create investment record
    const plans = [
      { id: "1", name: "Basic Plan", profitRate: 5 },
      { id: "2", name: "Premium Plan", profitRate: 8 },
      { id: "3", name: "VIP Plan", profitRate: 12 }
    ];
    
    const plan = plans.find(p => p.id === transaction.investmentPlan) || 
                plans.find(p => p.name === transaction.investmentPlan) ||
                plans[0];

    const investment = await Investment.create({
      user: user._id,
      transaction: transaction._id,
      planName: plan.name,
      amount: transaction.amount,
      profitRate: plan.profitRate,
      expectedProfit: transaction.amount * (plan.profitRate / 100),
      startDate: new Date(),
      endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      status: "active"
    });

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Investment Approved ✅",
      `Your investment of $${transaction.amount} in ${plan.name} has been approved and activated. Expected profit: $${investment.expectedProfit.toFixed(2)}.`,
      "investment",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'INVESTMENT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      transaction: transaction,
      investment: investment,
      amount: transaction.amount,
      message: `Your investment of $${transaction.amount} has been approved`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment approved successfully", 
      data: { 
        transaction: transaction,
        investment: investment,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          totalInvested: user.totalInvested
        }
      }
    });
  } catch (error) { 
    console.error('Investment approval error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment approval failed" 
    }); 
  }
});

// ================== MANUAL TOP-UP ROUTES ==================

// Manual deposit top-up
app.post("/api/admin/user/:userId/topup-deposit", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, note } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        message: "Valid amount is required" 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    const oldDepositBalance = user.depositBalance;
    user.depositBalance += parseFloat(amount);
    await user.save();

    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: "admin_adjustment",
      amount: parseFloat(amount),
      status: "approved",
      adminNote: `Admin manual deposit top-up: $${amount}. ${note || ''}`,
      processed: true
    });

    // Send notification to user
    await sendNotification(
      user._id,
      "Deposit Top-Up Added ✅",
      `Admin has added $${amount} to your deposit balance. ${note || ''}`,
      "deposit",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(user._id.toString(), {
      type: 'DEPOSIT_TOPUP',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      amount: amount,
      transaction: transaction,
      message: `$${amount} has been added to your deposit balance`,
      timestamp: new Date().toISOString()
  });

    res.json({ 
      success: true,
      message: "Deposit top-up successful", 
      data: {
        user: {
          depositBalance: user.depositBalance,
          previousBalance: oldDepositBalance
        },
        transaction: transaction
      }
    });
  } catch (error) {
    console.error('Deposit top-up error:', error);
    res.status(500).json({ 
      success: false,
      message: "Deposit top-up failed" 
    });
  }
});

// ================== USER ROUTES ==================

// User Profile Routes
app.put("/api/user/profile", protect, updateUserLocation, async (req, res) => {
  try {
    const { name, bitcoinAccount, tetherTRC20Account, secretQuestion, secretAnswer } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name;
    if (bitcoinAccount) updateData.bitcoinAccount = bitcoinAccount;
    if (tetherTRC20Account) updateData.tetherTRC20Account = tetherTRC20Account;
    if (secretQuestion) updateData.secretQuestion = secretQuestion;
    if (secretAnswer) {
      const salt = await bcrypt.genSalt(10);
      updateData.secretAnswer = await bcrypt.hash(secretAnswer, salt);
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true }
    ).select("-password -secretAnswer -confirmPassword");

    await sendNotification(req.user._id, "Profile Updated", "Your profile information has been updated successfully.", "profile");

    res.json({ 
      success: true,
      message: "Profile updated successfully", 
      data: { user: updatedUser } 
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false,
      message: "Profile update failed" 
    });
  }
});

// Get current user data
app.get("/api/me", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          _id: user._id,
          username: user.username,
          name: user.name,
          email: user.email,
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          totalInvested: user.totalInvested,
          bitcoinAccount: user.bitcoinAccount,
          tetherTRC20Account: user.tetherTRC20Account,
          secretQuestion: user.secretQuestion,
          referralCode: user.referralCode,
          location: user.location,
          createdAt: user.createdAt
        }
      },
      message: "User data retrieved successfully"
    });
  } catch (error) {
    console.error('Get user data error:', error);
    res.status(500).json({ 
      success: false,
      message: "Failed to fetch user data" 
    });
  }
});

// Deposit Routes
app.post("/api/deposits", protect, updateUserLocation, upload.single('proof'), async (req, res) => {
  try {
    const { amount, walletAddress } = req.body;
    const proofFile = req.file;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        message: "Valid deposit amount is required" 
      });
    }
    
    if (!proofFile) {
      return res.status(400).json({ 
        success: false,
        message: "Proof of payment is required" 
      });
    }
    
    const transaction = await Transaction.create({
      user: req.user._id,
      type: "deposit",
      amount: parseFloat(amount),
      status: "pending",
      proof: proofFile.filename,
      walletAddress: walletAddress || "Default Wallet"
    });
    
    await sendNotification(
      req.user._id,
      "Deposit Submitted",
      `Your deposit of $${amount} has been submitted for approval.`,
      "deposit",
      transaction._id,
      "transaction"
    );
    
    res.json({ 
      success: true,
      message: "Deposit submitted for approval", 
      data: { transaction } 
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ 
      success: false,
      message: "Deposit submission failed" 
    });
  }
});

// Investment Routes
app.post("/api/investments", protect, updateUserLocation, async (req, res) => {
  try {
    const { planId, amount } = req.body;
    const user = await User.findById(req.user._id);

    const plans = [
      { id: "1", name: "Basic Plan", profitRate: 5, minDeposit: 50, maxDeposit: 1000 },
      { id: "2", name: "Premium Plan", profitRate: 8, minDeposit: 1001, maxDeposit: 5000 },
      { id: "3", name: "VIP Plan", profitRate: 12, minDeposit: 5001, maxDeposit: 20000 }
    ];

    const plan = plans.find(p => p.id === planId);
    if (!plan) return res.status(400).json({ 
      success: false,
      message: "Invalid investment plan" 
    });

    if (user.depositBalance < amount) {
      return res.status(400).json({ 
        success: false,
        message: "Insufficient deposit balance" 
      });
    }

    if (amount < plan.minDeposit || amount > plan.maxDeposit) {
      return res.status(400).json({ 
        success: false,
        message: `Amount must be between $${plan.minDeposit} and $${plan.maxDeposit} for ${plan.name}` 
      });
    }

    const transaction = await Transaction.create({
      user: user._id,
      type: "investment",
      amount: parseFloat(amount),
      status: "pending",
      investmentPlan: plan.name
    });

    await sendNotification(
      user._id,
      "Investment Request Submitted",
      `Your investment request of $${amount} in ${plan.name} has been submitted for approval.`,
      "investment",
      transaction._id,
      "transaction"
    );

    res.json({ 
      success: true,
      message: "Investment request submitted for approval", 
      data: {
        transaction,
        plan: {
          name: plan.name,
          profitRate: plan.profitRate,
          expectedProfit: (amount * plan.profitRate / 100).toFixed(2)
        }
      }
    });
  } catch (error) {
    console.error('Investment creation error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment request failed" 
    });
  }
});

// Investment Plans
app.get("/api/investment-plans", async (req, res) => {
  try {
    const plans = [
      {
        _id: "1",
        name: "Basic Plan",
        profitRate: 5,
        minDeposit: 50,
        maxDeposit: 1000,
        description: "Perfect for beginners with low risk",
        duration: "30 days"
      },
      {
        _id: "2", 
        name: "Premium Plan",
        profitRate: 8,
        minDeposit: 1001,
        maxDeposit: 5000,
        description: "Great returns for serious investors",
        duration: "30 days"
      },
      {
        _id: "3",
        name: "VIP Plan", 
        profitRate: 12,
        minDeposit: 5001,
        maxDeposit: 20000,
        description: "Maximum returns for VIP investors",
        duration: "30 days"
      }
    ];
    res.json({ success: true, data: plans });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user transactions
app.get("/api/user/transactions", protect, updateUserLocation, async (req, res) => {
  try {
    const { type } = req.query;
    const filter = { user: req.user._id };
    if (type && type !== 'all') filter.type = type;
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({
      success: true,
      data: transactions,
      message: "Transactions retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user referrals
app.get("/api/user/referrals", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('referrals', 'username email createdAt totalInvested');
    
    res.json({
      success: true,
      data: {
        totalReferrals: user.referrals.length,
        referralCode: user.referralCode,
        referrals: user.referrals
      },
      message: "Referrals retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user investments
app.get("/api/user/investments", protect, updateUserLocation, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: investments,
      message: "Investments retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user notifications
app.get("/api/user/notifications", protect, updateUserLocation, async (req, res) => {
  try {
    const notifications = await Notification.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    const unreadCount = await Notification.countDocuments({ 
      user: req.user._id, 
      isRead: false 
    });
    
    res.json({
      success: true,
      data: {
        notifications,
        unreadCount
      },
      message: "Notifications retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Serve uploaded files
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));

// ================== ROOT ROUTE ==================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Galaxy Digital Holdings API Server',
    version: '2.1.0',
    endpoints: {
      auth: '/api/register, /api/login',
      user: '/api/user/*',
      admin: '/api/admin/*',
      health: '/api/health'
    },
    timestamp: new Date().toISOString()
  });
});

// ================== ERROR HANDLING ==================
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 5MB.'
      });
    }
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 WebSocket server available at ws://localhost:${PORT}/ws`);
  console.log(`🔑 Default Admin credentials: admin/admin123`);
  console.log(`🌍 Location tracking: Enabled with enhanced IP detection`);
  console.log(`🔒 CORS: Enabled for all origins with comprehensive configuration`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});