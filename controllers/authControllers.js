// ✅ BẮT BUỘC: Đặt dòng này lên đầu tiên để nạp biến môi trường
require('dotenv').config();

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// --- HÀM TIỆN ÍCH TÁI SỬ DỤNG ---

/**
 * ✅ HÀM TRUNG TÂM: Tìm user bằng googleId hoặc email, hoặc tạo mới.
 * Hàm này được tái sử dụng cho cả luồng web (Passport) và mobile (verifyIdToken).
 * @param {object} profile - Object chứa thông tin user từ Google.
 * @param {string} profile.googleId - ID của người dùng từ Google.
 * @param {string} profile.email - Email của người dùng.
 * @param {string} profile.fullname - Tên đầy đủ của người dùng.
 * @param {string} profile.avatar - URL ảnh đại diện.
 * @returns {Promise<User>} - Trả về một user document từ Mongoose.
 */
const findOrCreateUserFromGoogle = async (profile) => {
    // 1. Tìm user dựa trên googleId
    let user = await User.findOne({ googleId: profile.googleId });
    if (user) {
        return user;
    }

    // 2. Nếu không có, tìm dựa trên email để liên kết tài khoản đã có
    user = await User.findOne({ email: profile.email });
    if (user) {
        user.googleId = profile.googleId;
        user.avatar = user.avatar || profile.avatar; // Chỉ cập nhật avatar nếu chưa có
        user.isVerified = true; // Email từ Google mặc định đã xác thực
        await user.save();
        return user;
    }

    // 3. Nếu không có cả hai, tạo một user hoàn toàn mới
    const newUser = new User({
        googleId: profile.googleId,
        fullname: profile.fullname,
        email: profile.email,
        avatar: profile.avatar,
        isVerified: true,
        password: null, // Không có mật khẩu vì đăng nhập qua Google
    });
    
    await newUser.save();
    return newUser;
};

// --- HÀM EXPORT CHO PASSPORT STRATEGY ---

/**
 * ✅ HÀM CHO PASSPORT: Được gọi bởi GoogleStrategy sau khi Google xác thực thành công.
 * Nhiệm vụ chính là chuẩn hóa profile và gọi hàm findOrCreateUserFromGoogle.
 */
const findOrCreateUserForPassport = async (accessToken, refreshToken, profile, done) => {
    try {
        const userProfile = {
            googleId: profile.id,
            email: profile.emails[0].value,
            fullname: profile.displayName,
            avatar: profile.photos[0].value,
        };
        const user = await findOrCreateUserFromGoogle(userProfile);
        // Trả về user cho Passport để Passport gắn vào req.user
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
};

// --- CONTROLLER CHÍNH ---

const authController = {
    // REGISTER (Email & Password)
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
                fullname,
                email,
                password: hashedPassword,
            });
            const user = await newUser.save();
            const { password: _, ...userWithoutPassword } = user._doc;
            res.status(201).json({ message: 'User registered successfully', user: userWithoutPassword });
        } catch (error) {
            console.error('Error registering user:', error);
            res.status(500).json({ error: 'Error registering user' });
        }
    },

    // LOGIN (Email & Password)
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

            // Gửi refresh token trong httpOnly cookie để bảo mật
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

    // ✅ VERIFY GOOGLE TOKEN (Mobile Flow)
    verifyGoogleToken: async (req, res) => {
        const { idToken } = req.body;
        if (!idToken) {
            return res.status(400).json({ message: "ID token is required." });
        }
        try {
            // Xác thực token với Google
            const ticket = await client.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const payload = ticket.getPayload();
            
            // Chuẩn hóa profile để gọi hàm tái sử dụng
            const userProfile = {
                googleId: payload.sub,
                email: payload.email,
                fullname: payload.name,
                avatar: payload.picture,
            };

            // ✅ Gọi hàm tái sử dụng
            const user = await findOrCreateUserFromGoogle(userProfile);

            // Tạo token và trả về cho client
            const accessToken = authController.generateAccessToken(user);
            const { password, ...userWithoutPassword } = user._doc;
            
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
};

// Export controller chính và hàm cho Passport
module.exports = { authController, findOrCreateUserForPassport };