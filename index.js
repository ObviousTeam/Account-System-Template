const AWS = require('aws-sdk');
const CryptoJS = require('crypto-js');
const validator = require('validator');
const fs = require('fs');
const express = require('express');
const rateLimit = require("express-rate-limit");
const path = require('path');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));  // sends req and res to other files

const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, // 5 attempts
    message: "Too many login attempts. Please try again later."
});

const dynamodb = new AWS.DynamoDB({
  region: 'us-east-1',
  accessKeyId: 'YOUR_ACCESS_KEY_ID',
  secretAccessKey: 'YOUR_SECRET_ACCESS_KEY'
});

const {createget, createpost} = require('#createaccount')
const {loginget, loginpost} = require('#login');
const {recoversendget, recoversendpost, recoverchangeget, recoverchangepost} = require('#recover');


app.get('/create', createget)
app.post('/create', loginLimiter, createpost)

app.get('/login', loginget)
app.post('/login', loginLimiter, loginpost);

app.get('/recoversend', recoversendget)
app.post('/recoversend',loginLimiter, recoversendpost)

app.get('/recoverget', recoverchangeget)
app.post('/recoverget',loginLimiter, recoverchangepost)

const server = app.listen(3000, () => {
  console.log(`Express running → PORT ${server.address().port}`);
});
