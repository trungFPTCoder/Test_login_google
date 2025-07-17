const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Cần cho callback

// ✅ Import authController đã được tái cấu trúc
const { authController } = require('../controllers/authControllers'); 
const middlewareController = require('../controllers/middlewareController');

// --- Email & Password Routes ---
router.post('/register', authController.registerUser);
router.post('/login', authController.loginUser);
router.post('/refreshToken', authController.requestRefreshToken);
router.post('/logout', middlewareController.verifyToken, authController.userLogout);

// --- Google OAuth Routes (Web Redirect Flow) ---

// Route 1: Bắt đầu quá trình, chuyển hướng người dùng đến Google
router.get(
    "/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

// Route 2: Route callback mà Google sẽ chuyển hướng về sau khi người dùng đồng ý
router.get(
    "/google/callback",
    // Middleware của passport để xử lý thông tin từ Google
    passport.authenticate("google", {
        failureRedirect: `${process.env.DEEP_LINK_SCHEME}login?error=AuthenticationFailed`,
        session: false // ✅ Quan trọng: Không tạo session, chúng ta sẽ dùng JWT
    }),
    // Hàm này chỉ chạy khi `passport.authenticate` ở trên thành công
    (req, res) => {
        // Passport đã xử lý và gắn user vào req.user
        const user = req.user; 

        // Tạo JWT của riêng bạn
        const accessToken = authController.generateAccessToken(user);
        const { password, ...userWithoutPassword } = user._doc;
        const userString = encodeURIComponent(JSON.stringify(userWithoutPassword));

        // Chuyển hướng người dùng về lại client (mobile app) với token
        console.log(`🚀 Redirecting user ${user.email} to deep link...`);
        res.redirect(`${process.env.DEEP_LINK_SCHEME}login?token=${accessToken}&user=${userString}`);
    }
);

// --- Google Token Verification (Mobile Flow) ---
// Route này dành cho luồng mobile app gửi thẳng idToken lên server
router.post('/google/verify', authController.verifyGoogleToken);

module.exports = router;