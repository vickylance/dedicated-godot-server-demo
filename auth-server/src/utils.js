import jwt from 'jsonwebtoken';
import { ACCESS_TOKEN_EXPIRY } from './config';

const generateAccessToken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });
};

const getPasswordRegEx = () => {
  return new RegExp('^[a-zA-Z0-9]{3,30}$');
};

const getUserConfirmationUrl = (emailToken) => {
  return `http://${process.env.PUBLIC_HOST}:${process.env.PUBLIC_PORT}/api/v1/user/confirmation/${emailToken}`;
};

const getResetPasswordUrl = (resetPasswordToken) => {
  return `http://${process.env.PUBLIC_HOST}:${process.env.PUBLIC_PORT}/password/reset/${resetPasswordToken}`;
};

const getLoginUrl = () => {
  return `http://${process.env.PUBLIC_HOST}:${process.env.PUBLIC_PORT}/login`;
};

export {
  generateAccessToken,
  getPasswordRegEx,
  getUserConfirmationUrl,
  getResetPasswordUrl,
  getLoginUrl,
};
