import jwt from 'jsonwebtoken';

function verifyToken(req, res, next) {
  const token = req.header('auth-token');
  if (!token) {
    return res.status(401).send('Access Denied');
  }

  try {
    const verified = jwt.verify(token, process.env.TOKEN_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    if (err) {
      return res.status(401).send('Invalid Token');
    }
  }
}

export default verifyToken;
