// ✅ BẮT BUỘC: Đặt dòng này lên đầu tiên để nạp biến môi trường
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session"); // ✅ Thêm express-session
const os = require('os');

// Import models & controllers cần thiết cho Passport
const User = require('./models/User'); // ✅ Cần User model
const { findOrCreateUser } = require('./controllers/authControllers'); // ✅ Import hàm logic

// Import các routes
const authRoutes = require('./Route/auth');
const productRoutes = require('./Route/productRoute');
const commentRoutes = require('./Route/commentRoute');
const userRoutes = require('./Route/userRoute');

const app = express();

// --- KẾT NỐI DATABASE ---
const connectToMongo = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ Connected to MongoDB");
    } catch (err) {
        console.error("❌ Could not connect to MongoDB", err);
        process.exit(1);
    }
};
connectToMongo();

// --- MIDDLEWARE ---
app.use(cors());
// ✅ Bỏ cookieParser vì express-session đã xử lý session cookie
app.use(express.json());

// ✅ Cấu hình session, phải nằm trước passport.initialize()
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Thêm dòng này vào file .env
    resave: false,
    saveUninitialized: true,
  })
);

// ✅ Khởi tạo passport và passport session
app.use(passport.initialize());
app.use(passport.session());


// --- CẤU HÌNH PASSPORT ---
// ✅ Toàn bộ cấu hình Passport nên đặt ở file server chính cho rõ ràng

// Cấu hình chiến lược Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/v1/auth/google/callback`, // ✅ Đảm bảo URL này khớp với route
    },
    findOrCreateUser // ✅ Hàm xử lý logic sau khi xác thực thành công
  )
);

// Lưu ID người dùng vào session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Lấy thông tin người dùng từ ID trong session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});


// --- ROUTES ---
// ✅ Đổi tên route cho giống của thầy và để client dễ gọi
app.use("/v1/auth", authRoutes); 
app.use("/v1/products", productRoutes);
app.use("/v1/comments", commentRoutes);
app.use("/v1/users", userRoutes);

// --- START SERVER ---
function getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

const ip = getLocalIp();
const PORT = process.env.PORT || 8000;
app.listen(PORT, ip, () => {
    console.log(`🚀 Server is running on http://${ip}:${PORT}`);
});