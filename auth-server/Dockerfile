FROM node:12

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

ENV PORT=8080 \
  PUBLIC_PORT=5000

EXPOSE 8080

CMD ["npm", "start"]
