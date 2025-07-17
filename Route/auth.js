const authController = require('../controllers/authControllers');
const middlewareController = require('../controllers/middlewareController');
const passport = require('passport');
const jwt = require('jsonwebtoken');

const routes = require('express').Router();
// Register a new user
// POST http://10.13.11.129:8000/v1/auth/register
routes.post('/register', authController.registerUser);

// Login a user
// POST http://10.13.11.129:8000/v1/auth/login
routes.post('/login', authController.loginUser);

// Refresh user token
// POST http://10.13.11.129:8000/v1/auth/refreshToken
routes.post('/refreshToken', authController.requestRefreshToken);

// Logout a user
// POST http://10.13.11.129:8000/v1/auth/logout
routes.post('/logout', middlewareController.verifyToken, authController.userLogout);



// Google login
routes.get(
  '/google/login/web',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);


// Endpoint 2: URL Callback mà Google sẽ gọi lại
// Nó phải được thêm vào "Authorized redirect URIs" trên Google Cloud Console.
routes.get(
  '/google/callback',
  // Passport sẽ xử lý việc trao đổi code lấy token và profile
  passport.authenticate('google', { 
    failureRedirect: '/api/auth/login/failed', // Chuyển hướng nếu thất bại
    session: false // Không tạo session cookie
  }),
  // Nếu thành công, middleware này sẽ được gọi
  (req, res) => {
    // `req.user` được Passport gán sau khi xác thực thành công
    const user = req.user;

    // Tạo JWT token của ứng dụng bạn
    const payload = { user: { id: user.id } };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' });

    // Dữ liệu người dùng cần gửi về app
    const userData = { id: user.id, fullName: user.fullName, email: user.email };

    // Tạo deep link để trả token và user data về ứng dụng
    const deepLink = `myproductapp://login-success?token=${encodeURIComponent(token)}&user=${encodeURIComponent(JSON.stringify(userData))}`;

    // Chuyển hướng trình duyệt đến deep link đó
    // Trình duyệt sẽ kích hoạt mở ứng dụng di động
    res.redirect(deepLink);
  }
);

// Endpoint 3: Xử lý khi đăng nhập thất bại
routes.get('/login/failed', (req, res) => {
    const deepLink = `myproductapp://login-failed?error=AuthenticationFailed`;
    res.redirect(deepLink);
});

module.exports = routes;