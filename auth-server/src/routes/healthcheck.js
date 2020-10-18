import express from 'express';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: HealthCheck
 *   description: Checks the health of the API.
 */

/**
 * @swagger
 * path:
 *  /healthcheck:
 *    get:
 *      summary: Checks the health status of the API.
 *      tags: [HealthCheck]
 *      responses:
 *        "200":
 *          description: The API is healthy.
 *          content:
 *            application/json:
 *              schema:
 *                uptime:
 *                  type: string
 *                  description: The time until the server is running.
 *                msg:
 *                  type: string
 *                  description: OK message
 *                timestamp:
 *                  type: string
 *                  description: Current server timestamp
 *        "503":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.get('/', async (_req, res) => {
  // optional: add further things to check (e.g. connecting to database)
  const healthcheck = {
    uptime: process.uptime(),
    msg: 'OK',
    timestamp: Date.now(),
  };
  try {
    res.status(200).send(healthcheck);
  } catch (err) {
    healthcheck.message = err;
    res.status(503).send({ msg: err });
  }
});

export default router;
