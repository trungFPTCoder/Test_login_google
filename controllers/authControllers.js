const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/User');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/**
 * ✅ HÀM MỚI: Được Passport-Google-Strategy gọi sau khi xác thực thành công.
 * Tìm user trong CSDL bằng googleId, nếu không có thì tạo mới.
 * (Hàm này được export để index.js có thể import và sử dụng)
 */
exports.findOrCreateUser = async (accessToken, refreshToken, profile, done) => {
  try {
    // Tìm user dựa trên googleId
    let user = await User.findOne({ googleId: profile.id });

    if (user) {
      return done(null, user); // ✅ Nếu tìm thấy, trả về user đó
    }

    // Nếu không tìm thấy, kiểm tra xem có email đó chưa để liên kết
    user = await User.findOne({ email: profile.emails[0].value });
    if (user) {
        user.googleId = profile.id;
        user.avatar = user.avatar || profile.photos[0].value; // Cập nhật avatar nếu chưa có
        user.isVerified = true;
        await user.save();
        return done(null, user);
    }

    // Nếu không có cả googleId và email, tạo user mới
    const newUser = new User({
      googleId: profile.id,
      fullname: profile.displayName,
      email: profile.emails[0].value,
      avatar: profile.photos[0].value,
      isVerified: true, // Email từ Google đã được xác thực
    });
    
    await newUser.save();
    done(null, newUser);
  } catch (error) {
    done(error, null);
  }
};

/**
 * ✅ HÀM MỚI: Được gọi sau khi passport.authenticate trong route callback thành công.
 * Tạo JWT và chuyển hướng người dùng về ứng dụng client với token.
 */
exports.googleCallback = (req, res) => {
  // Passport đã xác thực thành công và gắn user vào req.user
  const user = req.user; 
  const accessToken = jwt.sign({ id: user.id, admin: user.admin }, process.env.JWT_ACCESS_KEY, { expiresIn: '1d' });

  // Chuẩn bị thông tin trả về cho client
  const { password, ...userWithoutPassword } = user._doc;
  const userString = encodeURIComponent(JSON.stringify(userWithoutPassword));
  
  // Chuyển hướng về app với token và thông tin user
  const redirectUrl = `${process.env.DEEP_LINK_SCHEME}login?token=${accessToken}&user=${userString}`;
  
  console.log(`🚀 Redirecting user ${user.email} to deep link...`);
  res.redirect(redirectUrl);
};


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
    },
    // ✅ HÀM MỚI: XÁC THỰC ID TOKEN TỪ MOBILE APP
    verifyGoogleToken: async (req, res) => {
        const { idToken } = req.body; // Nhận idToken từ body của request POST

        if (!idToken) {
            return res.status(400).json({ message: "ID token is required." });
        }

        try {
            // Xác thực token với Google
            const ticket = await client.verifyIdToken({
                idToken: idToken,
                audience: process.env.GOOGLE_CLIENT_ID, // Web Client ID
            });
            const payload = ticket.getPayload();
            
            // Lấy thông tin người dùng từ payload
            const { sub: googleId, email, name, picture } = payload;

            // Tìm hoặc tạo người dùng trong cơ sở dữ liệu của bạn
            let user = await User.findOne({ googleId: googleId });

            if (!user) {
                // Kiểm tra xem email đã tồn tại với tài khoản thường chưa
                user = await User.findOne({ email: email });
                if (user) {
                    // Nếu có, liên kết tài khoản
                    user.googleId = googleId;
                    // (Tùy chọn) Cập nhật tên và ảnh đại diện
                    user.fullname = user.fullname || name;
                    user.avatar = user.avatar || picture;
                    await user.save();
                } else {
                    // Nếu không, tạo người dùng mới
                    user = await new User({
                        googleId: googleId,
                        email: email,
                        fullname: name,
                        avatar: picture,
                        // Mật khẩu có thể để trống vì họ đăng nhập qua Google
                    }).save();
                }
            }

            // Tạo Access Token và Refresh Token của riêng bạn
            const accessToken = authController.generateAccessToken(user);
            const refreshToken = authController.generateRefreshToken(user);
            // (Bạn có thể lưu refreshToken vào cookie hoặc gửi về client)

            const { password, ...userWithoutPassword } = user._doc;
            
            // Trả về thông tin người dùng và token cho mobile app
            res.status(200).json({ 
                message: "Google sign-in successful",
                user: userWithoutPassword, 
                accessToken: accessToken 
            });

        } catch (error) {
            console.error("Google token verification failed:", error);
            res.status(401).json({ message: "Invalid Google token." });
        }
    },
};


// ✅ Ghép các hàm đã export ở trên vào object authController để có thể gọi từ route
// Điều này giúp giữ cấu trúc code của bạn mà vẫn tách bạch được logic
authController.findOrCreateUser = exports.findOrCreateUser;
authController.googleCallback = exports.googleCallback;

module.exports = authController;