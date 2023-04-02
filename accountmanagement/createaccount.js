exports.createget = (req, res) => {
	const path = require('path');
	res.sendFile(path.join(__dirname, '..', 'templates', 'account/createaccount.html'));
}

exports.createpost = (req, res) => {
	const bcrypt = require('bcryptjs');
	const crypto = require('crypto');
	const AWS = require('aws-sdk');
	const fs = require('fs');
	const validator = require('validator');
	const CryptoJS = require('crypto-js');
	const sanitizeHtml = require('sanitize-html');
	const salt = crypto.randomBytes(12).toString('hex');

	const dynamodb = new AWS.DynamoDB({
		region: 'us-east-1',
		accessKeyId: process.env['aws_access_key'],
		secretAccessKey: process.env['aws_secret_access_key']
	});

	const inputusername = req.body.username;
	const inputpassword = req.body.password;
	const inputemail = req.body.email;

	const username = sanitizeHtml(inputusername, {
		allowedTags: [],
		allowedAttributes: {}
	});

	const password = sanitizeHtml(inputpassword, {
		allowedTags: [],
		allowedAttributes: {}
	});

	const email = sanitizeHtml(inputemail, {
		allowedTags: [],
		allowedAttributes: {}
	});

	if (!validator.isAlphanumeric(username)) {
		return res.status(400).send('Invalid username format');
	}

	if (!validator.isAlphanumeric(password)) {
		return res.status(400).send('Invalid password format');
	}

	if (!validator.isEmail(email)) {
		return res.status(400).send('Invalid email format');
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
			fs.writeFile('createerrors.txt', err, {
				flag: 'a+'
			}, err => {});
			console.error(err);
		} else {
			const item = data.Item;
			const exists = !!item; // Convert item to boolean

			if (exists) {
				res.send('username already exists')
			} else {
				const emailcryptionkey = process.env['decryption_key']
				const params = {
					TableName: process.env['table_name'],
					Item: {
						username: {
							S: username
						},
						password: {
							S: bcrypt.hashSync(password, salt)
						},
						email: {
							S: CryptoJS.AES.encrypt(email, emailcryptionkey).toString()
						},
						chatbantime: {
							N: '0'
						},
						reports: {
							N: '0'
						},
					}
				};

				dynamodb.putItem(params, (err, data) => {
					if (err) {
						res.status(500).send('Sorry, There has been an error. We have already notified our devloper team about this error. Please try again later')
						fs.writeFile('createerrors.txt', err, {
							flag: 'a+'
						}, err => {});
						console.error(err);
					} else {
						console.log('Item added successfully');
						req.session.email = email
						req.session.username = password;
					}
				});
			}
		}
	});

}