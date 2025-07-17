// ✅ BẮT BUỘC: Đặt dòng này lên đầu tiên để nạp biến môi trường
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const os = require('os');

// ✅ Import hàm xử lý logic cho Passport từ controller đã được tái cấu trúc
const { findOrCreateUserForPassport } = require('./controllers/authControllers');

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
app.use(express.json());

// ✅ Khởi tạo passport (Không cần session)
app.use(passport.initialize());

// --- CẤU HÌNH PASSPORT ---
// Cấu hình chiến lược Google OAuth, sử dụng hàm logic đã import
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: `${process.env.BACKEND_URL}/v1/auth/google/callback`,
        },
        findOrCreateUserForPassport // ✅ Hàm xử lý logic nhất quán
    )
);

// ✅ Không cần `passport.serializeUser` và `passport.deserializeUser` vì không dùng session.

// --- ROUTES ---
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