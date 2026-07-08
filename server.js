require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB with better error handling
console.log('🔍 Attempting to connect to MongoDB...');
console.log('📊 MONGODB_URI:', process.env.MONGODB_URI ? 'Exists' : 'Missing');

mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ MongoDB Connected Successfully');
    console.log('📁 Database:', mongoose.connection.db.databaseName);
    console.log('🔗 Host:', mongoose.connection.host);
})
.catch(err => {
    console.error('❌ MongoDB Connection Error:');
    console.error('📊 Error Message:', err.message);
    console.error('📊 Error Name:', err.name);
    console.error('📊 Error Code:', err.code);
    
    if (err.message.includes('bad auth')) {
        console.error('💡 Authentication failed! Check your username and password in MONGODB_URI');
    } else if (err.message.includes('ENOTFOUND')) {
        console.error('💡 Host not found! Check your cluster name in MONGODB_URI');
    } else if (err.message.includes('timed out')) {
        console.error('💡 Connection timed out! Check your network and MongoDB Atlas IP whitelist');
    }
    
    console.log('💡 Continuing with in-memory storage for testing...');
    // Don't exit, let the app run with no DB for testing
});

// Define User Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, default: null },
    authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
    googleId: { type: String, default: null },
    googleProfilePic: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: null },
    isActive: { type: Boolean, default: true }
});

// Check if mongoose is connected before using model
let User;
try {
    User = mongoose.model('User');
} catch (error) {
    User = mongoose.model('User', UserSchema);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: 'propai_secret_key_2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Flash messages
app.use(flash());

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Auth middleware
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash('error_msg', 'Please login first');
    res.redirect('/login');
};

// Routes
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.render('login', {
        messages: req.flash()
    });
});

app.get('/register', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.render('register', {
        messages: req.flash()
    });
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        console.log('📝 Registration attempt for:', email);

        if (!name || !email || !password || !confirmPassword) {
            req.flash('error_msg', 'All fields are required');
            return res.redirect('/register');
        }

        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match');
            return res.redirect('/register');
        }

        if (password.length < 6) {
            req.flash('error_msg', 'Password must be at least 6 characters');
            return res.redirect('/register');
        }

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        
        if (existingUser) {
            req.flash('error_msg', 'Email already registered');
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name: name.trim(),
            email: email.toLowerCase().trim(),
            password: hashedPassword,
            authProvider: 'local',
            createdAt: new Date()
        });

        await user.save();
        console.log('✅ User created successfully!');

        req.flash('success_msg', 'Registration successful! Please login.');
        res.redirect('/login');
    } catch (error) {
        console.error('❌ Registration error:', error);
        req.flash('error_msg', 'Registration failed. Please try again.');
        res.redirect('/register');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('🔐 Login attempt for:', email);

        if (!email || !password) {
            req.flash('error_msg', 'All fields are required');
            return res.redirect('/login');
        }

        const user = await User.findOne({ email: email.toLowerCase().trim() });
        
        if (!user) {
            req.flash('error_msg', 'Invalid credentials');
            return res.redirect('/login');
        }

        if (!user.password) {
            req.flash('error_msg', 'This account uses Google login');
            return res.redirect('/login');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            req.flash('error_msg', 'Invalid credentials');
            return res.redirect('/login');
        }

        user.lastLogin = new Date();
        await user.save();

        req.logIn(user, (err) => {
            if (err) {
                console.error('❌ Login error:', err);
                req.flash('error_msg', 'Login failed');
                return res.redirect('/login');
            }
            console.log('✅ Login successful for:', user.email);
            req.flash('success_msg', 'Welcome back!');
            return res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        req.flash('error_msg', 'Login failed');
        res.redirect('/login');
    }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }
        res.render('dashboard', {
            user: user,
            messages: req.flash()
        });
    } catch (error) {
        console.error('❌ Dashboard error:', error);
        req.flash('error_msg', 'Something went wrong');
        res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('❌ Logout error:', err);
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('❌ Session destroy error:', err);
            }
            res.redirect('/login');
        });
    });
});

// Debug route
app.get('/debug/db', (req, res) => {
    const state = mongoose.connection.readyState;
    const states = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    res.json({
        connected: state === 1,
        state: states[state] || 'unknown',
        database: mongoose.connection.db ? mongoose.connection.db.databaseName : 'not connected',
        host: mongoose.connection.host || 'unknown'
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    req.flash('error_msg', 'Something went wrong');
    res.redirect('/login');
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});