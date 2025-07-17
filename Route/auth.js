const express = require('express');
const router = express.Router();

// ✅ CHỈ CẦN MỘT DÒNG REQUIRE NÀY
// Đảm bảo tên file trong thư mục controllers là 'authControllers.js'
const authController = require('../controllers/authControllers'); 
const middlewareController = require('../controllers/middlewareController');

// --- Email & Password Routes ---

// Register a new user
// POST http://<your-ip>:8000/v1/auth/register
router.post('/register', authController.registerUser);

// Login a user
// POST http://<your-ip>:8000/v1/auth/login
router.post('/login', authController.loginUser);

// Refresh user token
// POST http://<your-ip>:8000/v1/auth/refreshToken
router.post('/refreshToken', authController.requestRefreshToken);

// Logout a user
// POST http://<your-ip>:8000/v1/auth/logout
router.post('/logout', middlewareController.verifyToken, authController.userLogout);


// --- Google OAuth Routes ---

// Bắt đầu quá trình đăng nhập với Google (App gọi URL này)
router.get('/google/login/web', authController.googleLogin);

// URL callback mà Google sẽ gọi sau khi người dùng đăng nhập
router.get('/google/callback', authController.googleCallback);

router.post('/google/verify', authController.verifyGoogleToken);

// (Tùy chọn) Lấy thông tin profile người dùng (yêu cầu token)
// GET http://<your-ip>:8000/v1/auth/profile
// router.get('/profile', authController.protect, authController.getProfile); // Tạm thời comment lại nếu chưa dùng đến

module.exports = router;
