exports.loginget = (req, res) => {
	const path = require('path');
	res.sendFile(path.join(__dirname, '..', 'templates', 'account/login.html'));
}

exports.loginpost = (req, res) => {
	const bcrypt = require('bcryptjs');
	const AWS = require('aws-sdk');
	const validator = require('validator');
	const fs = require('fs');
	const sanitizeHtml = require('sanitize-html');
	const CryptoJS = require('crypto-js');

	const dynamodb = new AWS.DynamoDB({
		region: 'us-east-1',
		accessKeyId: process.env['aws_access_key'],
		secretAccessKey: process.env['aws_secret_access_key']
	});

	const inputusername = req.body.username;
	const inputpassword = req.body.password;

	const username = sanitizeHtml(inputusername, {
		allowedTags: [],
		allowedAttributes: {}
	});

	const password = sanitizeHtml(inputpassword, {
		allowedTags: [],
		allowedAttributes: {}
	});

	if (!validator.isAlphanumeric(username)) {
		return res.status(400).send('Invalid username format');
	}

	if (!validator.isAlphanumeric(password)) {
		return res.status(400).send('Invalid password format');
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
			fs.writeFile('loginerrors.txt', err, {
				flag: 'a+'
			}, err => {});
			console.error(err);
		} else {
			const item = data.Item;
			const exists = !!item;

			if (exists) {
				if (bcrypt.compareSync(password, item.password.S)) {
					const emaildecreptionkey = process.env['decryption_key']
					const bytes = CryptoJS.AES.decrypt(item.email.S, emaildecreptionkey);
					const decryptedEmail = bytes.toString(CryptoJS.enc.Utf8);
					req.session.email = decryptedEmail
					req.session.username = username;
				} else {
					res.status(401).send('Incorrect password');
				}
			} else {
				res.status(401).send('User does not exist');
			}
		}
	});
};