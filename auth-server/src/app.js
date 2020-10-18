import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import http from 'http';
import path from 'path';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import WebSocket from 'ws';
import { getVar, putVar } from '@gd-com/utils';
import { v4 } from 'uuid';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import sequelize from './db';

// import routes
import routes from './routes';

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
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// routers middleware
app.use('/', routes);

// Swagger set up
const options = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Time to document that Express API you built',
      version: '1.0.0',
      description:
        'A test project to understand how easy it is to document and Express API',
      license: {
        name: 'MIT',
        url: 'https://choosealicense.com/licenses/mit/',
      },
      contact: {
        name: 'Swagger',
        url: 'https://swagger.io',
        email: 'Info@SmartBear.com',
      },
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT}/api/v1`,
      },
    ],
  },
  apis: [
    path.resolve(__dirname, './models/User.js'),
    path.resolve(__dirname, './routes/user.js'),
    path.resolve(__dirname, './routes/healthcheck.js'),
  ],
};
const specs = swaggerJsdoc(options);
app.use('/api/v1/docs', swaggerUi.serve);
app.get(
  '/api/v1/docs',
  swaggerUi.setup(specs, {
    explorer: true,
  })
);

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
