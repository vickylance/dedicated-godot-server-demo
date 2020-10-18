import redis from 'redis';
import chalk from 'chalk';

const redisClient = redis.createClient({
  port: process.env.REDIS_PORT || 6379,
  host: process.env.REDIS_HOST || 'localhost',
});
redisClient.on('connect', () => {
  console.log(chalk.green('Connected to REDIS cache!'));
});

export default redisClient;
