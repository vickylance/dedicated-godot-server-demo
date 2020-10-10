import path from 'path';
import { Sequelize } from 'sequelize';

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.resolve('db/database.sqlite3'),
  logging: console.log,
});

export default sequelize;
