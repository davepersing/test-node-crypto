var crypto = require('crypto');
var ref = require('ref');
var fs = require('fs');
var buffer = require('buffer');

/*
playerId: 12345
bundleId: com.playdom.game
timestamp: 1403241398421
salt: this is my salt
signature: 6/yMbmV+ym4MJhh4G3qT/AnBQQs=
'{"playerId":"12345", "bundleId":"com.company.game", "timestamp":1403241398421, "salt":"this is my salt", "signature":"sig"}'
*/

function generateData(playerId, bundleId, timestamp, salt) {

	console.log('playerId: %s', playerId);
	console.log('bundleId: %s', bundleId);
	console.log('timestamp: %d', timestamp);
	console.log('salt: %s', salt);

	fs.readFile('./private_key.pem', function (err, data) {
		hmac = crypto.createHmac('sha1', data);

		hmac.setEncoding('base64');

		var buf = ref.alloc('uint64');
		ref.writeUInt64BE(buf, 0, timestamp);

		var payloadBuf = Buffer.concat([
											new Buffer(playerId, 'utf8'),
											new Buffer(bundleId, 'utf8'),
											buf, 
											new Buffer(salt, 'base64')
											]);

		hmac.write(payloadBuf);
		hmac.end();

		console.log ('signature: %s', hmac.read());
	});
}

generateData('12345', 'com.company.game', Date.now(), 'this is my salt');
