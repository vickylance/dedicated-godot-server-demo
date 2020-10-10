import dotenv from 'dotenv';
import express from 'express';
import http from 'http';
import path from 'path';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import WebSocket from 'ws';
import { getVar, putVar } from '@gd-com/utils';
import { v4 } from 'uuid';
import sequelize from './db';

// import routes
import indexRouter from './routes/index';
import userRouter from './routes/user';

dotenv.config();

const app = express();

// Connect to db
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
})();

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// routers middleware
app.use('/', indexRouter);
app.use('/api/v1/user', userRouter);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.id = v4();

  ws.on('message', (message) => {
    const receiveBuff = Buffer.from(message);
    const receive = getVar(receiveBuff);
    console.log(receive);
    const buffer = putVar('Vignesh');
    ws.send(buffer);
  });
});

export { app };
export default server;
