import { DataTypes, Model } from 'sequelize';
import sequelize from '../db';

class User extends Model {}

User.init(
  {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [6, 255],
          msg: 'Name should be at least 6 characters long',
        },
      },
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        len: {
          args: [6, 255],
          msg: 'Username should be at least 6 characters long',
        },
      },
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        len: {
          args: [6, 255],
          msg: 'Email should be at least 6 characters long',
        },
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [16, 1024],
          msg: 'Password should be at least 6 characters long',
        },
      },
    },
    confirmed: {
      type: DataTypes.BOOLEAN,
      allowNull: true,
      defaultValue: false,
    },
  },
  {
    sequelize,
    modelName: 'User',
  }
);

User.sync();

export default User;
