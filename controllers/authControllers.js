const bcrypt = require('bcrypt');
const User = require('../models/User'); // Import the User model
const jwt = require('jsonwebtoken'); // Import the JWT library
const { OAuth2Client } = require("google-auth-library");

const client = new OAuth2Client(process.env.GOOGLE_WEB_CLIENT_ID);

let refreshTokens = [];
const authController = {
    //REGISTER
    registerUser: async (req, res) => {
        const { fullname, email, password } = req.body;
        try {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already exists' });
            }
            const salt = await bcrypt.genSalt(10); // Generate a salt for hashing
            const hashedPassword = await bcrypt.hash(password, salt); // Hash the password with the salt
            const newUser = new User({
                fullname: fullname,
                password: hashedPassword,
                email: email,
            });
            const user = await newUser.save();
            res.status(201).json({ message: 'User registered successfully', user });
        } catch (error) {
            console.error('Error registering user:', error);
            res.status(500).json({ error: 'Error registering user' });
        }
    },
    //LOGIN
    generateAccessToken: (user) => {
        return jwt.sign({ id: user._id, admin: user.admin }, process.env.JWT_ACCESS_KEY, { expiresIn: '1d' });//set thời gian hết hạn cho access token là 1d
    },
    generateRefreshToken: (user) => {
        return jwt.sign({ id: user._id, admin: user.admin }, process.env.JWT_REFRESH_KEY, { expiresIn: '365d' });
    },
    // lấy access token bằng const data = await response.json(); data.accessToken;
    loginUser: async (req, res) => {
        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            const isPasswordValid = await bcrypt.compare(req.body.password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid password', user });
            }
            if (user && isPasswordValid) {
                const accessToken = authController.generateAccessToken(user);
                const refreshToken = authController.generateRefreshToken(user);
                refreshTokens.push(refreshToken);
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'strict', // CSRF protection
                });

                const { password, ...userWithoutPassword } = user._doc; // Destructure to remove the password field
                res.status(200).json({ ...userWithoutPassword, accessToken }); // Send the user data without the password
            }
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    },
    requestRefreshToken: async (req, res) => {
        //take refresh token from user
        const refreshToken = req.cookies.refreshToken;
        // console.log("Refresh token: ", refreshToken);
        if (!refreshToken) return res.status(401).json("You are not authenticated!"+ refreshToken);
        jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
            if (err) return res.status(403).json("Refresh token is not valid!");
            refreshTokens = refreshTokens.filter((token) => token !== refreshToken); // Remove the used refresh token
            //create new access token and refresh token
            const newAccessToken = authController.generateAccessToken(user);
            const newRefreshToken = authController.generateRefreshToken(user);
            refreshTokens.push(newRefreshToken);//added 13/05/2025
            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict', // CSRF protection
            });
            res.status(200).json({ accessToken: newAccessToken });
        });
    },
    userLogout: async (req, res) => {
        res.clearCookie('refreshToken');
        refreshTokens = refreshTokens.filter((token) => token !== req.cookies.refreshToken); // Remove the used refresh token
        res.status(200).json("Logged out successfully!");
    }
}
module.exports = authController;

exports.googleLogin = async (req, res) => {
    // Frontend sẽ gửi idToken lên body
    const { idToken } = req.body; 
    
    if (!idToken) {
        return res.status(400).json({ msg: 'ID Token is required.' });
    }

    try {
        // Xác thực idToken với Google
        const ticket = await client.verifyIdToken({
            idToken: idToken,
            // Backend cần xác thực token được tạo ra từ cả 3 nền tảng
            audience: [ 
                process.env.GOOGLE_WEB_CLIENT_ID,
                process.env.GOOGLE_ANDROID_CLIENT_ID,
                process.env.GOOGLE_IOS_CLIENT_ID,
            ],
        });
        
        const { name, email, email_verified } = ticket.getPayload();

        if (!email_verified) {
            return res.status(400).json({ msg: 'Google email is not verified.' });
        }

        // Tìm người dùng trong DB bằng email
        let user = await User.findOne({ email });

        // Nếu người dùng chưa tồn tại, tạo mới
        if (!user) {
            user = new User({
                fullName: name,
                email,
                password: null, 
                status: 'verified', 
            });
            await user.save();
        }

        // Tạo JWT token của ứng dụng và trả về cho client
        const payload = { user: { id: user.id } };
        const appToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' });

        res.json({ 
            token: appToken, 
            user: { id: user.id, fullName: user.fullName, email: user.email } 
        });

    } catch (error) {
        console.error("Google login error:", error);
        res.status(500).json({ msg: 'Google authentication failed' });
    }
};