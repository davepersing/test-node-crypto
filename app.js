var crypto = require('crypto');
var express = require('express');
var fs = require('fs');
var ref = require('ref');
var cert = fs.readFileSync('./rsacert.pem');


var times = [];

var app = express();

app.use(express.json());

app.get('/info', function (req, res) {
	var total = 0;

	for (var i = 0; i < times.length; i ++) {
		total += times[i];
	}
	var avg = total / times.length;

	console.log('length: ' + times.length);
	console.log('average time : %d', avg);
	res.end('average time: ' + avg + 'ms\n');
})

app.get('/verify', function (req, res) {
	validate("12345", "com.company.game", "1403304772152", "this is my salt", "kevppAKaj5opL34lOXR2NZhh1GQ=");
	res.end();
});

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

	console.log('key: %s', cert);

	var result = validate(playerId, bundleId, timestamp, salt, signature);
	console.log('result : ' + result);
	res.end(result);
});

var server = app.listen(3000, function () {
	console.log('Listening on %d', 3000);
});

function validate(playerId, bundleId, timestamp, salt, signature) {
	var t0 = Date.now();

	var buf = ref.alloc('uint64');
	ref.writeUInt64BE(buf, 0, timestamp);

	var verifier = crypto.createVerify('sha1');
	var payloadBuf = Buffer.concat([
										new Buffer(playerId, 'utf8'),
										new Buffer(bundleId, 'utf8'),
										buf, 
										new Buffer(salt, 'base64')
										]);
	verifier.update(payloadBuf);

	var result = verifier.verify(cert, signature, "base64");
	times.push(Date.now() - t0);
	return result;
}