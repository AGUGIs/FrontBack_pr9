const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Требуется авторизация',
      message: 'Добавьте заголовок Authorization: Bearer <token>'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Токен истёк',
        message: 'Пожалуйста, войдите в систему снова'
      });
    }
    return res.status(401).json({ 
      error: 'Неверный токен',
      message: 'Предоставьте действительный JWT токен'
    });
  }
}

module.exports = { authMiddleware, JWT_SECRET };