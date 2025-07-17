const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User'); // Đảm bảo đường dẫn đúng

// --- Cấu hình Passport.js với chiến lược Google ---
// Phần này sẽ được Node.js thực thi khi module được require, và nó sẽ cấu hình passport.
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}${process.env.CALLBACK_URL}`
  },
  // Hàm này sẽ được gọi sau khi Google xác thực người dùng thành công
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Tìm hoặc tạo người dùng trong database
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
          // Liên kết tài khoản nếu đã có email
          user.googleId = profile.id;
          await user.save();
        } else {
          // Tạo người dùng mới
          user = await new User({
            googleId: profile.id,
            fullname: profile.displayName,
            email: profile.emails[0].value,
          }).save();
        }
      }
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));

// --- Controller chính ---
const authController = {
    //REGISTER
    registerUser: async (req, res) => {
        const { fullname, email, password } = req.body;
        try {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already exists' });
            }
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const newUser = new User({
                fullname: fullname,
                password: hashedPassword,
                email: email,
            });
            const user = await newUser.save();
            const { password: _, ...userWithoutPassword } = user._doc;
            res.status(201).json({ message: 'User registered successfully', user: userWithoutPassword });
        } catch (error) {
            console.error('Error registering user:', error);
            res.status(500).json({ error: 'Error registering user' });
        }
    },

    //LOGIN
    loginUser: async (req, res) => {
        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            if (!user.password) {
                return res.status(400).json({ message: 'This account is registered with Google. Please use Google login.' });
            }
            const isPasswordValid = await bcrypt.compare(req.body.password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid password' });
            }
            
            const accessToken = authController.generateAccessToken(user);
            const refreshToken = authController.generateRefreshToken(user);

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
            });

            const { password, ...userWithoutPassword } = user._doc;
            res.status(200).json({ user: userWithoutPassword, accessToken });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    },
    
    // --- GOOGLE AUTH LOGIC (Đã được tích hợp vào đây) ---
    googleLogin: passport.authenticate('google', { 
      scope: ['profile', 'email'],
      session: false 
    }),

    googleCallback: (req, res) => {
      passport.authenticate('google', { session: false, failureRedirect: '/login-failed' }, (err, user, info) => {
        if (err || !user) {
          return res.redirect(`${process.env.DEEP_LINK_SCHEME}login?error=AuthenticationFailed`);
        }
    
        const token = authController.generateAccessToken(user);
        const { password, ...userWithoutPassword } = user._doc;
        const userString = encodeURIComponent(JSON.stringify(userWithoutPassword));
        
        console.log(`🚀 Redirecting to deep link with token...`);
        res.redirect(`${process.env.DEEP_LINK_SCHEME}login?token=${token}&user=${userString}`);
      })(req, res);
    },

    // --- TOKEN GENERATION & MANAGEMENT ---
    generateAccessToken: (user) => {
        return jwt.sign({ id: user.id, admin: user.admin }, process.env.JWT_ACCESS_KEY, { expiresIn: '1d' });
    },
    generateRefreshToken: (user) => {
        return jwt.sign({ id: user.id, admin: user.admin }, process.env.JWT_REFRESH_KEY, { expiresIn: '365d' });
    },

    requestRefreshToken: async (req, res) => {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.status(401).json("You are not authenticated!");
        
        jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
            if (err) return res.status(403).json("Refresh token is not valid!");
            
            const newAccessToken = authController.generateAccessToken(user);
            const newRefreshToken = authController.generateRefreshToken(user);

            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
            });
            res.status(200).json({ accessToken: newAccessToken });
        });
    },

    userLogout: async (req, res) => {
        res.clearCookie('refreshToken');
        res.status(200).json("Logged out successfully!");
    }
};

module.exports = authController;
