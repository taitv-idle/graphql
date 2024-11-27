const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const authHeader = req.get('Authorization');

    // Nếu không có header Authorization
    if (!authHeader) {
        req.isAuth = false;
        return next(); // Dừng thực thi và chuyển sang middleware tiếp theo
    }

    const token = authHeader.split(' ')[1];

    // Nếu token không tồn tại hoặc không đúng định dạng
    if (!token) {
        req.isAuth = false;
        return next();
    }

    let decodedToken;
    try {
        // Xác minh token
        decodedToken = jwt.verify(token, 'truongvantai');
    } catch (err) {
        req.isAuth = false;
        return next(); // Token không hợp lệ
    }

    // Nếu không giải mã được token
    if (!decodedToken) {
        req.isAuth = false;
        return next();
    }

    // Token hợp lệ
    req.userId = decodedToken.userId;
    req.isAuth = true;
    next();
};
