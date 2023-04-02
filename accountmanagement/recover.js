exports.recoversendget = (req, res) => {
	const path = require('path');
	res.sendFile(path.join(__dirname, '..', 'templates', 'account/recoversend.html'));
}

exports.recoversendpost = (req, res) => {
	const crypto = require('crypto');
	const bcrypt = require('bcryptjs');
	const sanitizeHtml = require('sanitize-html');
	const AWS = require('aws-sdk');
	const CryptoJS = require('crypto-js');
	const fs = require('fs');
	const validator = require('validator');
	const nodemailer = require('nodemailer');

	const dynamodb = new AWS.DynamoDB({
		region: 'us-east-1',
		accessKeyId: process.env['aws_access_key'],
		secretAccessKey: process.env['aws_secret_access_key']
	});

	const inputusername = req.body.username;

	const username = sanitizeHtml(inputusername, {
		allowedTags: [],
		allowedAttributes: {}
	});

	if (!validator.isAlphanumeric(username)) {
		return res.status(400).send('Invalid username format');
	}

	const params = {
		TableName: process.env['table_name'],
		Key: {
			username: {
				S: username
			}
		}
	};

	dynamodb.getItem(params, (err, data) => {
		if (err) {
			res.status(500).send('Sorry, There has been an error. We have already notified our devloper team about this error. Please try again later')
			fs.writeFile('recovererrors.txt', err, {
				flag: 'a+'
			}, err => {});
			console.error(err);
		} else {
			const item = data.Item;
			if (!item) {
				console.log('Item not found');
			} else {
				const email = item.email.S;
			}
		}
	});

	if (email == "") {
		res.status(400).send('I am sorry but this account does not have an email linked to it. This account is not recoverable')
	} else {
		const emailcryptionkey = process.env['decryption_key']
		const decrypted_email = CryptoJS.AES.decrypt(encryptedData, emailcryptionkey).toString(CryptoJS.enc.Utf8);

		var transporter = nodemailer.createTransport({
			service: process.env['nodemailer_service'],
			auth: {
				user: process.env['nodemailer_email'],
				pass: process.env['nodemailer_pass']
			}
		});
		const code = crypto.randomBytes(8).toString('hex')
		var mailOptions = {
			from: process.env['nodemailer_email'],
			to: decrypted_email,
			subject: 'Your Recovery Code',
			text: 'Your recovery code is ' + code + '. This code will expire in 5 minutes.'
		};

		transporter.sendMail(mailOptions, function(err, info) {
			if (err) {
				res.status(500).send('Sorry, There has been an error. We have already notified our devloper team about this error. Please try again later')
				fs.writeFile('recovererrors.txt', err, {
					flag: 'a+'
				}, err => {});
				console.log(err);
			} else {
				console.log('Email sent')
				setTimeout(() => {
					const time = false;
				}, 5 * 60 * 1000);
			}
		});

	}

}
exports.recoverchangeget = (req, res) => {
	const path = require('path');
	res.sendFile(path.join(__dirname, '..', 'templates', 'account/recoverget.html'));
}

exports.recoverchangepost = (req, res) => {
	const crypto = require('crypto');
	const bcrypt = require('bcryptjs');
	const AWS = require('aws-sdk');
	const sanitizeHtml = require('sanitize-html');
	const validator = require('validator');
	const CryptoJS = require('crypto-js');

	const salt = crypto.randomBytes(12).toString('hex');

	const dynamodb = new AWS.DynamoDB({
		region: 'us-east-1',
		accessKeyId: process.env['aws_access_key'],
		secretAccessKey: process.env['aws_secret_access_key']
	});

	const inputcode = req.body.code;
	const inputpassword = req.body.password;

	const code = sanitizeHtml(inputcode, {
		allowedTags: [],
		allowedAttributes: {}
	});

	const password = sanitizeHtml(inputpassword, {
		allowedTags: [],
		allowedAttributes: {}
	});

	if (!validator.isAlphanumeric(code)) {
		return res.status(400).send('Invalid username format');
	}

	if (!validator.isAlphanumeric(password)) {
		return res.status(400).send('Invalid username format');
	}

	if (time) {
		const params = {
			TableName: process.env['table_name'],
			Key: {
				id: {
					S: username
				}
			},
			UpdateExpression: 'SET #password = :password',
			ExpressionAttributeNames: {
				'#password': 'password'
			},
			ExpressionAttributeValues: {
				':password': {
					S: bcrypt.hashSync(password, salt),
				}
			}
		};

		dynamodb.updateItem(params, (err, data) => {
			if (err) {
				res.status(500).send('Sorry, There has been an error. We have already notified our devloper team about this error. Please try again later')
				fs.writeFile('recovererrors.txt', err, {
					flag: 'a+'
				}, err => {});
				console.error(err);
			} else {
				console.log('Item updated successfully');
			}
		});
	}
}
