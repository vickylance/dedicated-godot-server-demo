import express from 'express';
import user from './user';
import healthcheck from './healthcheck';

const router = express.Router();

router.get('/', (_req, res) => {
  res.render('index', { title: 'Express' });
});
router.use('/api/v1//user', user);
router.use('/api/v1//healthcheck', healthcheck);

export default router;
