const jwt = require('jsonwebtoken'); // Import the JWT library

const middlewareController = {
    //verifyToken
    verifyToken: (req, res, next) => {
        const token = req.headers.token || req.headers['authorization']; // Lấy token từ header, có thể là 'token' hoặc
        if (token) {
            const accessToken = token.split(" ")[1];
            jwt.verify(accessToken, process.env.JWT_ACCESS_KEY, (err, user) => {
                if (err) return res.status(403).json("Token is not valid!");//kiểm tra có phải là người dùng đó không nếu không thì chặn
                req.user = user;
                next();//đúng thì cho đi tiếp
            });
        }
        else {
            return res.status(401).json("You are not authenticated!");//nếu không có token thì không cho đi tiếp (chưa có JWT)
        }
    },
    //Chỉ được xóa khi là admin khi là chính mình (req.param.id là id của user nhập từ client)
    verifyTokenAndAdmin: (req, res, next) => {
        middlewareController.verifyToken(req, res, () => {
            if (req.user.id == req.param.id || req.user.admin) {
                next();
            } else {
                return res.status(403).json("You are not allowed to do that!");
            }
        });
    }
}
module.exports = middlewareController;