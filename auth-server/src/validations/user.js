import Joi from '@hapi/joi';

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
    password: Joi.string()
      .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$'))
      .required(),
    repeat_password: Joi.ref('password'),
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

export { registerValidation, loginValidation, deleteValidation };
