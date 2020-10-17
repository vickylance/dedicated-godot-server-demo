import Joi from '@hapi/joi';
import { getPasswordRegEx } from '../utils';

const registerValidation = (data) => {
  const userValidation = Joi.object({
    name: Joi.string().min(6).max(255).required(),
    username: Joi.string().alphanum().min(6).max(30).required(),
    email: Joi.string()
      .min(6)
      .max(255)
      .required()
      .email({ minDomainSegments: 2 })
      .required(),
    password: Joi.string().pattern(getPasswordRegEx()).required(),
    confirm_password: Joi.ref('password'),
  });
  return userValidation.validate(data);
};

const loginValidation = (data) => {
  const userValidation = Joi.object({
    emailOrUsername: Joi.alternatives()
      .try(
        Joi.string().min(6).max(255).email({ minDomainSegments: 2 }),
        Joi.string().alphanum().min(6).max(30)
      )
      .required(),
    password: Joi.string().min(6).max(30).required(),
  });
  return userValidation.validate(data);
};

const deleteValidation = (data) => {
  const userValidation = Joi.object({
    password: Joi.string().min(6).max(30).required(),
  });
  return userValidation.validate(data);
};

const resetPasswordRequestValidation = (data) => {
  const userValidation = Joi.object({
    emailOrUsername: Joi.alternatives()
      .try(
        Joi.string().min(6).max(255).email({ minDomainSegments: 2 }),
        Joi.string().alphanum().min(6).max(30)
      )
      .required(),
  });
  return userValidation.validate(data);
};

const resetPasswordValidation = (data) => {
  const userValidation = Joi.object({
    password: Joi.string().pattern(getPasswordRegEx()).required(),
    confirm_password: Joi.ref('password'),
  });
  return userValidation.validate(data);
};

const changePasswordValidation = (data) => {
  const userValidation = Joi.object({
    old_password: Joi.string().pattern(getPasswordRegEx()).required(),
    new_password: Joi.ref('old_password'),
    confirm_password: Joi.ref('old_password'),
  });
  return userValidation.validate(data);
};

const resendEmailValidation = (data) => {
  const userValidation = Joi.object({
    emailOrUsername: Joi.alternatives()
      .try(
        Joi.string().min(6).max(255).email({ minDomainSegments: 2 }),
        Joi.string().alphanum().min(6).max(30)
      )
      .required(),
  });
  return userValidation.validate(data);
};

export {
  registerValidation,
  loginValidation,
  deleteValidation,
  resetPasswordRequestValidation,
  resetPasswordValidation,
  changePasswordValidation,
  resendEmailValidation,
};
