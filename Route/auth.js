const express = require('express');
const router = express.Router();
const passport = require('passport');

const authController = require('../controllers/authControllers'); 
const middlewareController = require('../controllers/middlewareController');

// --- Email & Password Routes ---
router.post('/register', authController.registerUser);
router.post('/login', authController.loginUser);
router.post('/refreshToken', authController.requestRefreshToken);
router.post('/logout', middlewareController.verifyToken, authController.userLogout);


// --- Google OAuth Routes (Web Redirect Flow) ---

// ✅ Route để bắt đầu quá trình đăng nhập với Google
router.get(
  "/google", // Đổi tên cho ngắn gọn
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// ✅ Route callback mà Google sẽ chuyển hướng về
router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${process.env.DEEP_LINK_SCHEME}login?error=AuthenticationFailed`, // ✅ Chuyển hướng về app nếu lỗi
    session: false, // Không tạo session của passport sau khi xong
  }),
  authController.googleCallback // ✅ Chạy hàm controller sau khi xác thực thành công
);


// --- Google Token Verification (Mobile Flow) ---
// ✅ Giữ lại route này cho luồng đăng nhập từ mobile app (không dùng web redirect)
router.post('/google/verify', authController.verifyGoogleToken);

module.exports = router;