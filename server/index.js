require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  googleId: { type: String, sparse: true },
  email: { type: String, required: true, unique: true },
  firstName: { type: String, required: true, default: 'User' },
  lastName: { type: String, required: true, default: '' },
  password: String,
  profilePicture: { type: String, default: '' },
  isEmailVerified: { type: Boolean, default: false },
  verificationOTP: String,
  otpExpires: Date
  ,resetPasswordToken: String,
  resetPasswordExpires: Date
});

const User = mongoose.model('User', userSchema);

// Passport Configuration
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Google Profile:', JSON.stringify(profile, null, 2));
    
    // Extract user information from profile
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
    const firstName = profile.name ? profile.name.givenName : profile.displayName.split(' ')[0];
    const lastName = profile.name ? profile.name.familyName : profile.displayName.split(' ').slice(1).join(' ');
    const profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : '';

    // First check if user exists by Google ID
    let user = await User.findOne({ googleId: profile.id });
    
    if (!user) {
      // If no user found by Google ID, check by email
      user = await User.findOne({ email });
      
      if (user) {
        // If user exists with email, update their Google ID
        user.googleId = profile.id;
        user.firstName = firstName;
        user.lastName = lastName;
        user.profilePicture = profilePicture;
        await user.save();
      } else {
        // Create new user if doesn't exist at all
        user = await User.create({
          googleId: profile.id,
          email,
          firstName,
          lastName,
          profilePicture
        });
      }
    } else {
      // Update existing user's information
      user.firstName = firstName;
      user.lastName = lastName;
      user.profilePicture = profilePicture;
      await user.save();
    }
    
    return done(null, user);
  } catch (err) {
    console.error('Google Auth Error:', err);
    return done(err, null);
  }
}));

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../')));

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60 // Session TTL (1 day)
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // Cookie expiry (1 day)
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Auth Routes
const bcrypt = require('bcrypt');
const { generateOTP, sendOTPEmail, sendResetPasswordEmail } = require('../api/lib/email');

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Generate OTP and set expiry
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      verificationOTP: otp,
      otpExpires,
      isEmailVerified: false
    });

    // Send verification email
    const emailSent = await sendOTPEmail(email, otp);

    if (!emailSent) {
      await User.findByIdAndDelete(user._id);
      return res.status(500).json({ message: 'Failed to send verification email' });
    }

    res.json({ 
      message: 'Please check your email for verification code',
      email: email
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Error creating account' });
  }
});

// Verify OTP endpoint
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ 
      email,
      verificationOTP: otp,
      otpExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification code' });
    }

    // Mark email as verified
    user.isEmailVerified = true;
    user.verificationOTP = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Log the user in
    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Error logging in' });
      }
      res.json({ message: 'Email verified successfully' });
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Error verifying email' });
  }
});

// Resend OTP endpoint
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email, isEmailVerified: false });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or already verified' });
    }

    // Generate new OTP
    const otp = generateOTP();
    user.verificationOTP = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();

    // Send new verification email
    const emailSent = await sendOTPEmail(email, otp);
    if (!emailSent) {
      return res.status(500).json({ message: 'Failed to send verification email' });
    }

    res.json({ message: 'New verification code sent' });
  } catch (error) {
    console.error('Resend error:', error);
    res.status(500).json({ message: 'Error resending verification code' });
  }
});

app.get('/api/auth/google',
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })
);

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    if (!user.isEmailVerified) {
      return res.status(400).json({ 
        message: 'Please verify your email first',
        needsVerification: true,
        email: email
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Error logging in' });
      }
      res.json({ message: 'Login successful' });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Check Auth Status
app.get('/api/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      isAuthenticated: true, 
      user: {
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        profilePicture: req.user.profilePicture
      } 
    });
  } else {
    res.json({ isAuthenticated: false });
  }
});

// Logout Route
app.get('/api/auth/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Dashboard Page
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(path.join(__dirname, '../dashboard.html'));
  } else {
    res.redirect('/login');
  }
});

// Test email endpoint (remove in production)
app.get('/api/test-email', async (req, res) => {
  try {
    const nodemailer = require('nodemailer');
    // Create test account
    const testAccount = await nodemailer.createTestAccount();
    console.log('Test account created:', testAccount);

    const { sendOTPEmail } = require('../api/lib/email');
    const testOTP = '123-456';
    console.log('Attempting to send email to:', process.env.GMAIL_USER);
    const result = await sendOTPEmail(process.env.GMAIL_USER, testOTP);
    res.json({ 
      success: result, 
      message: 'Check your email for test OTP',
      testAccount: testAccount 
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ 
      error: error.message,
      stack: error.stack
    });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Forgot password - send reset link
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });

    // Always respond with success to avoid leaking which emails exist
    if (!user) {
      return res.json({ message: 'If that account exists, we have sent a reset link to the email.' });
    }

    // Generate token and hashed token to store
    const token = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(token).digest('hex');

    user.resetPasswordToken = hashed;
    user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour
    await user.save();

  const base = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const link = `${base}/reset-password.html?token=${token}&email=${encodeURIComponent(email)}`;

    const sent = await sendResetPasswordEmail(email, link);
    if (!sent) {
      // don't reveal too much; remove token
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      return res.status(500).json({ message: 'Unable to send reset email' });
    }

    res.json({ message: 'If that account exists, we have sent a reset link to the email.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ message: 'Missing parameters' });
    if (newPassword.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ email, resetPasswordToken: hashed, resetPasswordExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired reset token' });

    // Hash and set new password
    const newHashed = await bcrypt.hash(newPassword, 10);
    user.password = newHashed;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});