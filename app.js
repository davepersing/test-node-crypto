var crypto = require('crypto');
var express = require('express');
var fs = require('fs');
var ref = require('ref');

var app = express();

app.use(express.json());

app.post('/verify', function (req, res) {
	var playerId = req.body.playerId;
	var bundleId = req.body.bundleId;
	var timestamp = req.body.timestamp;
	var salt = req.body.salt;
	var signature = req.body.signature;

	console.log('playerId: %s', playerId);
	console.log('bundleId: %s', bundleId);
	console.log('timestamp: %d', timestamp);
	console.log('salt: %s', salt);
	console.log('signature: %s', signature);

	fs.readFile('./rsacert.pem', function (err, data) {

		console.log('key: %s', data);

		var buf = ref.alloc('uint64');
		ref.writeUInt64BE(buf, 0, timestamp);

		var verifier = crypto.createVerify('sha1');
		verifier.update(playerId, 'utf8');
		verifier.update(bundleId, 'utf8');
		verifier.update(buf);
		verifier.update(salt, 'base64');

		var isValid = verifier.verify(data, signature, "base64");

		var result = {result: isValid};
		console.log(JSON.stringify(result));

		res.status(200).json(result);
		res.end();
	});
});

var server = app.listen(3000, function () {
	console.log('Listening on %d', 3000);
});
