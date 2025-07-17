// config/passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
require('dotenv').config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_WEB_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      // URL mà Google sẽ chuyển hướng về sau khi người dùng đồng ý.
      // Nó phải khớp chính xác với một trong các "Authorized redirect URIs"
      // bạn đã cấu hình trên Google Cloud Console.
      callbackURL: `${process.env.BACKEND_URL}/api/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      // Hàm này sẽ được gọi sau khi Google xác thực thành công.
      // `profile` chứa thông tin người dùng từ Google.
      try {
        const { id, displayName, emails, photos } = profile;
        const email = emails[0].value;

        // Tìm xem người dùng đã tồn tại trong DB chưa
        let user = await User.findOne({ email });

        if (user) {
          // Nếu đã tồn tại, chỉ cần trả về thông tin người dùng
          return done(null, user);
        } else {
          // Nếu chưa tồn tại, tạo một người dùng mới
          const newUser = await User.create({
            fullName: displayName,
            email,
            status: 'verified', // Tự động xác thực
          });
          return done(null, newUser);
        }
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// Passport cần hai hàm này để quản lý session, dù chúng ta không dùng session để đăng nhập
passport.serializeUser((user, done) => {
    done(null, user.id);
});
  
passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => done(err, user));
});