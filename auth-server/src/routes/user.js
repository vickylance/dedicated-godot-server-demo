import express from 'express';
import fs from 'fs';
import path from 'path';
import nunjucks from 'nunjucks';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import verifyToken from '../validations/verifyToken';
import rateLimiter from '../validations/rateLimiter';
import {
  generateAccessToken,
  getUserConfirmationUrl,
  getResetPasswordUrl,
  getLoginUrl,
} from '../utils';
import redisClient from '../cache';
import {
  registerValidation,
  loginValidation,
  deleteValidation,
  resetPasswordRequestValidation,
  resetPasswordValidation,
  changePasswordValidation,
  resendEmailValidation,
} from '../validations/user';
import transporter from '../transporter';
import { REFRESH_TOKEN_EXPIRY } from '../config';
import {
  INVALID_TOKEN,
  EMAIL_EXISTS,
  INVALID_PASSWORD,
  USERNAME_EXISTS,
  USER_ALREADY_CONFIRMED,
  USER_NOT_CONFIRMED,
  USER_NOT_EXISTS,
  DELETE_FAILED,
  REFRESH_TOKEN_EXPIRED,
  NEW_PASSWORD_MISMATCH,
} from '../constants/errors';
import {
  USER_CREATED,
  EMAIL_SENT,
  RESET_PASSWORD_EMAIL_SENT,
  LOGGED_IN,
  LOGGED_OUT,
  ACCOUNT_DELETED,
} from '../constants/success';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management
 */

/**
 * @swagger
 * path:
 *  /user/register:
 *    post:
 *      summary: Create a new user.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              name: string
 *              username: string
 *              email: string
 *              password: string
 *              confirm_password: string
 *            example:
 *              name: Vignesh S
 *              username: Vickylance
 *              email: vickylance@live.in
 *              password: Password@123
 *              confirm_password: Password@123
 *      responses:
 *        "201":
 *          description:
 *            When a user is successfully created.
 *            And a confirmation email is being sent to their email address.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *                user: integer
 *        "400":
 *          description:
 *            This is sent when the request body doesn't match the user validation schema.
 *            Or if the user's email or username is already present.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.post(
  '/register',
  rateLimiter(1, 60 * 5), // can register a new user per ip for 1 time in 5 mins
  async (req, res) => {
    // validate request body
    const { error } = registerValidation(req.body);
    if (error) {
      return res.status(400).json({ msg: error.details[0].message });
    }

    // Check if user already exists
    const emailExists = await User.findOne({
      where: { email: req.body.email },
    });
    if (emailExists) {
      return res.status(400).json({ msg: EMAIL_EXISTS });
    }
    const usernameExists = await User.findOne({
      where: { username: req.body.username },
    });
    if (usernameExists) {
      return res.status(400).json({ msg: USERNAME_EXISTS });
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // create new user
    const user = User.build({
      name: req.body.name,
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });

    try {
      // save user
      const savedUser = await user.save();

      // async email
      jwt.sign(
        { user: savedUser.id },
        process.env.EMAIL_SECRET,
        { expiresIn: '1d' },
        (err, emailToken) => {
          if (err) {
            console.error(err);
            return;
          }
          const url = getUserConfirmationUrl(emailToken);
          const template = fs.readFileSync(
            path.resolve(__dirname, '../templates/confirmEmail.njk'),
            'utf-8'
          );
          transporter.sendMail({
            to: savedUser.email,
            subject: 'Confirm email',
            html: nunjucks.renderString(template, { url }),
          });
          console.log('Email sent successfully');
        }
      );

      return res.status(201).json({ msg: USER_CREATED, user: savedUser.id });
    } catch (err) {
      return res.status(500).json({ msg: err });
    }
  }
);

/**
 * @swagger
 * path:
 *  /user/login:
 *    post:
 *      summary: Logins the user and returns the access token and refresh token
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              emailOrUsername:
 *                type: string
 *                description: The email or username of the user.
 *              password:
 *                type: string
 *                description: The password of the user.
 *      responses:
 *        "200":
 *          description: When a user is successfully logged in. Access token and refresh token is sent.
 *          content:
 *            headers:
 *              authorization:
 *                schema:
 *                  type: string
 *                description: Access Token for the logged in user.
 *            application/json:
 *              schema:
 *                msg:
 *                  type: string
 *                accessToken:
 *                  type: string
 *                  description: Access Token for the logged in user.
 *                refreshToken:
 *                  type: string
 *                  description: Refresh Token for the logged in user.
 *        "400":
 *          description:
 *            This is sent when the request body doesn't match the login validation schema.
 *            Or if the user's email/username and password doesn't match.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "401":
 *          description: Invalid password.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "403":
 *          description: User not confirmed.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "404":
 *          description: User does not exist.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.post('/login', rateLimiter(10, 30), async (req, res) => {
  // validate request body
  const { error } = loginValidation(req.body);
  if (error) {
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Check if user exists
  let user = false;
  user = await User.findOne({
    where: { email: req.body.emailOrUsername },
  });
  if (!user) {
    user = await User.findOne({
      where: { username: req.body.emailOrUsername },
    });
  }
  if (!user) {
    return res.status(404).json({ msg: USER_NOT_EXISTS });
  }

  // Check if user is confirmed
  if (!user.confirmed) {
    return res.status(403).json({ msg: USER_NOT_CONFIRMED });
  }

  // verify password
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(401).json({ msg: INVALID_PASSWORD });
  }

  // create and assign token
  const accessToken = generateAccessToken({ id: user.id });
  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.REFRESH_TOKEN_SECRET
  );
  // set the refresh token in cache
  redisClient.setex(user.id, REFRESH_TOKEN_EXPIRY, refreshToken);

  return res
    .status(200)
    .header('authorization', accessToken)
    .json({ msg: LOGGED_IN, accessToken, refreshToken });
});

/**
 * @swagger
 * path:
 *  /user/token:
 *    post:
 *      summary: Generates a new access token for the user using refresh token.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                token:
 *                  type: string
 *                  description: Refresh token.
 *      responses:
 *        "200":
 *          description: If the refresh token is valid and active a new access token is generated and sent.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  accessToken:
 *                    type: string
 *                    description: Generated new access token.
 *        "401":
 *          description: This is sent when the refresh token is not present.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  msg:
 *                    type: string
 *                    description: INVALID_TOKEN error message
 *              example:
 *        "403":
 *          description: This is sent when the refresh token is expired.
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                  msg:
 *                    type: string
 *                    description: REFRESH_TOKEN_EXPIRED error message
 *              example:
 *                token: invalid token
 */
router.post('/token', rateLimiter(10, 30), (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.status(401).json({ msg: INVALID_TOKEN });
  if (!redisClient.get(refreshToken))
    return res.status(403).json({ msg: REFRESH_TOKEN_EXPIRED });
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ msg: REFRESH_TOKEN_EXPIRED });
    const accessToken = generateAccessToken({ id: user.id });
    // update the refresh token expiry in cache
    redisClient.expire(user.id, REFRESH_TOKEN_EXPIRY);
    return res.status(200).json({ accessToken });
  });
});

/**
 * @swagger
 * path:
 *  /user/confirmation/:token:
 *    get:
 *      summary: Confirms the email address of the user.
 *      tags: [Users]
 *      responses:
 *        "304":
 *          description: User is confirmed and redirected to login page.
 *        "204":
 *          description: User already confirmed.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "404":
 *          description: User does not exist.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.get('/confirmation/:token', rateLimiter(1, 60), async (req, res) => {
  try {
    const { user } = jwt.verify(req.params.token, process.env.EMAIL_SECRET);

    // Check if the user exists
    const savedUser = await User.findOne({
      where: { id: user },
    });
    if (!savedUser) {
      return res.status(404).json({ msg: USER_NOT_EXISTS });
    }

    // Check if the user has already confirmed
    if (savedUser.confirmed) {
      return res.status(204).json({ msg: USER_ALREADY_CONFIRMED });
    }

    // Confirm the user
    await User.update(
      { confirmed: true },
      {
        where: {
          id: user,
        },
      }
    );
    return res.redirect(getLoginUrl());
    // return res.redirect('http://localhost:3000/login');
  } catch (err) {
    return res.status(500).json({ msg: err });
  }
});

/**
 * @swagger
 * path:
 *  /user/:id:
 *    delete:
 *      summary: Deletes the user's account if the current password is correct.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              password: string
 *      responses:
 *        "200":
 *          description: User is successfully deleted.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *                id: integer
 *        "400":
 *          description: Bad request as password not sent
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "403":
 *          description: Unauthorized due to invalid password.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.delete('/:id', verifyToken, rateLimiter(1, 60 * 5), async (req, res) => {
  // validate request body
  const { error } = deleteValidation(req.body);
  if (error) {
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Validate password
  const user = await User.findOne({
    where: { id: req.user.id },
  });
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(403).json({ msg: INVALID_PASSWORD });
  }

  // Delete the user
  // TODO: implement soft delete
  try {
    await User.destroy({ where: { id: req.user.id } });
    return res.status(200).json({ id: req.user.id, msg: ACCOUNT_DELETED });
  } catch (err) {
    return res.status(500).json({ msg: DELETE_FAILED });
  }
});

/**
 * @swagger
 * path:
 *  /user/logout:
 *    get:
 *      summary: Logs out the user and clears the user's refresh token
 *      tags: [Users]
 *      responses:
 *        "200":
 *          description: User is successfully logged out.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.get('/logout', verifyToken, rateLimiter(10, 30), async (req, res) => {
  try {
    redisClient.del(req.user.id);
    return res.status(200).json({ msg: LOGGED_OUT });
  } catch (err) {
    return res.status(500).json({ msg: err });
  }
});

/**
 * @swagger
 * path:
 *  /user/password/change:
 *    post:
 *      summary: Changes the users password if the current password is correct and the new passwords match the criteria.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              old_password:
 *                type: string
 *                description: Existing password of the user.
 *              new_password:
 *                type: string
 *                description: New password of the user.
 *              confirm_password:
 *                type: string
 *                description: Same as the new password of the user.
 *      responses:
 *        "200":
 *          description: When a user is successfully logged in. Access token and refresh token is sent.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *                id: integer
 *        "400":
 *          description: Bad request if the payload is empty or the new passwords do not match.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "403":
 *          description: Old password is wrong.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.post(
  '/password/change',
  verifyToken,
  rateLimiter(1, 60 * 5),
  async (req, res) => {
    // validate request body
    const { error } = changePasswordValidation(req.body);
    if (error) {
      return res.status(400).json({ msg: error.details[0].message });
    }
    if (req.body.new_password !== req.body.confirm_password) {
      return res.status(400).json({ msg: NEW_PASSWORD_MISMATCH });
    }

    // Validate password
    const user = await User.findOne({
      where: { id: req.user.id },
    });
    const validPassword = await bcrypt.compare(
      req.body.old_password,
      user.password
    );
    if (!validPassword) {
      return res.status(403).json({ msg: INVALID_PASSWORD });
    }

    // Change the password for the user
    try {
      const userWithNewPassword = User.build({
        password: req.body.new_password,
      });
      await userWithNewPassword.save({ where: { id: req.user.id } });
      return res.status(200).json({ msg: 'OK', id: req.user.id });
    } catch (err) {
      return res.status(500).json({ msg: DELETE_FAILED });
    }
  }
);

/**
 * @swagger
 * path:
 *  /user/password/reset:
 *    get:
 *      summary: Generate a password reset link and send to the user.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              emailOrUsername:
 *                type: string
 *                description: The email or username of the user.
 *      responses:
 *        "202":
 *          description: The reset email is being sent to the user.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "400":
 *          description: Bad request error sent when the email or username validation fails
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "404":
 *          description: User was not found.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.get('/password/reset', rateLimiter(1, 60 * 5), async (req, res) => {
  // TODO: implement rate limiting

  // validate request body
  const { error } = resetPasswordRequestValidation(req.body);
  if (error) {
    return res.status(400).json({ msg: error.details[0].message });
  }

  // check if the user exists
  let user = false;
  user = await User.findOne({
    where: { email: req.body.emailOrUsername },
  });
  if (!user) {
    user = await User.findOne({
      where: { username: req.body.emailOrUsername },
    });
  }
  if (!user) {
    return res.status(404).json({ msg: USER_NOT_EXISTS });
  }

  try {
    // send email with reset password link
    jwt.sign(
      { user: user.id },
      process.env.EMAIL_SECRET,
      { expiresIn: '1d' },
      (err, resetPasswordToken) => {
        if (err) {
          console.error(err);
          return;
        }
        const url = getResetPasswordUrl(resetPasswordToken);
        const template = fs.readFileSync(
          path.resolve(__dirname, '../templates/resetPassword.njk'),
          'utf-8'
        );
        transporter.sendMail({
          to: user.email,
          subject: 'Confirm email',
          html: nunjucks.renderString(template, { url }),
        });
      }
    );

    return res.status(202).json({ msg: RESET_PASSWORD_EMAIL_SENT });
  } catch (err) {
    return res.status(500).json({ msg: err });
  }
});

/**
 * @swagger
 * path:
 *  /user/password/:token:
 *    put:
 *      summary: Resets the password if the reset token is valid and the new password match the criteria.
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              password: string
 *              confirm_password: string
 *      responses:
 *        "200":
 *          description: New password has been reset successfully.
 *          content:
 *            application/json:
 *              schema:
 *                id: integer
 *        "400":
 *          description: Bad request error if the new password does not match the criteria.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "404":
 *          description: User was not found.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.patch(
  '/password/reset/:token',
  rateLimiter(1, 60 * 5),
  async (req, res) => {
    try {
      // TODO: check for last 5 passwords

      const { user } = jwt.verify(req.params.token, process.env.EMAIL_SECRET);

      // validate request body
      const { error } = resetPasswordValidation(req.body);
      if (error) {
        return res.status(400).json({ msg: error.details[0].message });
      }

      // Check if the user exists
      const savedUser = await User.findOne({
        where: { id: user.id },
      });
      if (!savedUser) {
        return res.status(404).json({ msg: USER_NOT_EXISTS });
      }

      // change the password
      const userWithNewPassword = User.build({ password: req.body.password });
      await userWithNewPassword.save({ where: { id: savedUser.id } });
      return res.status(200).json({ id: savedUser.id });
    } catch (err) {
      return res.status(500).json({ msg: err });
    }
  }
);

/**
 * @swagger
 * path:
 *  /user/resend-email:
 *    post:
 *      summary: Resend confirmation email to the user
 *      tags: [Users]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              emailOrUsername: string
 *      responses:
 *        "201":
 *          description: The confirmation email is sent successfully.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "400":
 *          description: Bad request error sent when the email or username validation fails
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "404":
 *          description: User was not found.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 *        "500":
 *          description: Internal server error.
 *          content:
 *            application/json:
 *              schema:
 *                msg: string
 */
router.post('/resend-email', rateLimiter(1, 60), async (req, res) => {
  // validate request body
  const { error } = resendEmailValidation(req.body);
  if (error) {
    return res.status(400).json({ msg: error.details[0].message });
  }

  // check if valid user
  let user = false;
  user = await User.findOne({
    where: { email: req.body.emailOrUsername },
  });
  if (!user) {
    user = await User.findOne({
      where: { username: req.body.emailOrUsername },
    });
  }
  if (!user) {
    return res.status(404).json({ msg: USER_NOT_EXISTS });
  }

  try {
    const emailToken = jwt.sign({ user: user.id }, process.env.EMAIL_SECRET, {
      expiresIn: '1d',
    });

    const url = getUserConfirmationUrl(emailToken);
    const template = fs.readFileSync(
      path.resolve(__dirname, '../templates/confirmEmail.njk'),
      'utf-8'
    );
    transporter.sendMail({
      to: user.email,
      subject: 'Confirm email',
      html: nunjucks.renderString(template, { url }),
    });

    return res.status(201).json({ msg: EMAIL_SENT });
  } catch (err) {
    return res.status(500).json({ msg: err });
  }
});

export default router;
