import redisClient from '../cache';

async function isOverLimit(ip, noOfRequest, timeLimit) {
  let result;
  try {
    result = await redisClient.incr(ip);
  } catch (err) {
    console.error('isOverLimit: could not increment key');
    throw err;
  }
  console.log(`${ip} has value: ${result}`);
  if (result > noOfRequest) {
    return true;
  }
  redisClient.expire(ip, timeLimit);
}

async function rateLimiter(req, res, next, noOfRequest, timeLimit) {
  // check rate limit
  const overLimit = await isOverLimit(req.ip, noOfRequest, timeLimit);
  if (overLimit) {
    res.status(429).json({ msg: 'Too many requests - Try again later' });
  }
  next();
}

export default rateLimiter;
