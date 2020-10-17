import { DataTypes, Model } from 'sequelize';
import sequelize from '../db';

class User extends Model {}

/**
 * @swagger
 *  components:
 *    schemas:
 *      User:
 *        type: object
 *        required:
 *          - name
 *          - username
 *          - email
 *          - password
 *          - confirmed
 *        properties:
 *          name:
 *            type: string
 *            description: Name of the user
 *          username:
 *            type: string
 *            description: Username of the user, needs to be unique.
 *          email:
 *            type: string
 *            format: email
 *            description: Email for the user, needs to be unique.
 *          password:
 *            type: string
 *            description: Hashed password for the user
 *          confirmed:
 *            type: boolean
 *            description: Email confirmation status of the user
 *        example:
 *           name: Alexander
 *           username: Alexus
 *           email: fake@email.com
 *           password: hashedPassword
 *           confirmed: true
 */
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
