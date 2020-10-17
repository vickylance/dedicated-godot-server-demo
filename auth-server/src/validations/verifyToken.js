import jwt from 'jsonwebtoken';
import { INVALID_TOKEN, ACCESS_DENIED } from '../constants/errors';

function verifyToken(req, res, next) {
  const authHeader = req.header('authorization');
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ msg: ACCESS_DENIED });
  }

  try {
    const verified = jwt.verify(
      token,
      process.env.TOKEN_SECRET,
      (err, user) => {
        if (err) return res.status(403).json({ msg: INVALID_TOKEN });
        req.user = user;
        next();
      }
    );
    req.user = verified;
    next();
  } catch (err) {
    if (err) {
      return res.status(500).send('System Error');
    }
  }
}

export default verifyToken;
