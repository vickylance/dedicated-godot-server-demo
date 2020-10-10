import express from 'express';
import fs from 'fs';
import path from 'path';
import nunjucks from 'nunjucks';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import verifyToken from '../validations/verifyToken';
import {
  registerValidation,
  loginValidation,
  deleteValidation,
} from '../validations/user';
import transporter from '../transporter';

const router = express.Router();

router.post('/register', async (req, res) => {
  // validate request body
  const { error } = registerValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  // Check if user already exists
  const emailExists = await User.findOne({ where: { email: req.body.email } });
  if (emailExists) {
    return res.status(400).send('Email already exists');
  }
  const usernameExists = await User.findOne({
    where: { username: req.body.username },
  });
  if (usernameExists) {
    return res.status(400).send('Username already exists');
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
        const url = `http://localhost:${process.env.PUBLIC_PORT}/api/v1/user/confirmation/${emailToken}`;
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

    return res.status(200).send({ user: savedUser.id });
  } catch (err) {
    return res.status(400).send(err);
  }
});

router.post('/login', async (req, res) => {
  // validate request body
  const { error } = loginValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
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
    return res.status(400).send('The username or email does not exists');
  }

  // Check if user is confirmed
  if (!user.confirmed) {
    return res.status(400).send('Please confirm your email to login');
  }

  // verify password
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(400).send('Invalid password');
  }

  // create and assign token
  const token = jwt.sign({ id: user.id }, process.env.TOKEN_SECRET);
  return res.header('auth-token', token).send({ token });
});

router.get('/confirmation/:token', async (req, res) => {
  try {
    const { user } = jwt.verify(req.params.token, process.env.EMAIL_SECRET);

    // Check if the user exists
    const savedUser = await User.findOne({
      where: { id: user },
    });
    if (!savedUser) {
      return res.status(400).send('User does not exist');
    }

    // Check if the user has already confirmed
    if (savedUser.confirmed) {
      return res.status(400).send('User is already confirmed');
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
    return res.status(200).send('Email confirmed please login');
    // return res.redirect('http://localhost:3000/login');
  } catch (err) {
    return res.status(400).send(err);
  }
});

router.delete('/:id', verifyToken, async (req, res) => {
  // validate request body
  const { error } = deleteValidation(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  // Validate password
  const user = await User.findOne({
    where: { id: req.user.id },
  });
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(400).send('Invalid password');
  }

  // Check if user exists and delete
  try {
    const docs = await User.destroy({ where: { id: req.user.id } });
    return res.status(200).send({ id: req.user.id, docs });
  } catch (err) {
    return res.status(400).send('Delete failed');
  }
});

export default router;
