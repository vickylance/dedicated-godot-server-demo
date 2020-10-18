import chalk from 'chalk';
import redisClient from '../cache';

async function isOverLimit(ip, noOfRequest, timeLimit) {
  let result;
  try {
    result = await redisClient.incr(ip);
  } catch (err) {
    console.error(chalk.red(`Rate limited: ${ip}`));
    throw err;
  }
  if (result > noOfRequest) {
    return true;
  }
  redisClient.expire(ip, timeLimit);
}

function rateLimiter(noOfRequest, timeLimit) {
  return async (req, res, next) => {
    // check rate limit
    const overLimit = await isOverLimit(req.ip, noOfRequest, timeLimit);
    if (overLimit) {
      let timeLeft;
      redisClient.ttl(req.ip, (_err, data) => {
        timeLeft = data;
      });
      res
        .status(429)
        .json({ msg: `Too many requests - Try again in ${timeLeft}` });
    }
    next();
  };
}

export default rateLimiter;
