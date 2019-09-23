var express = require('express');
var app = express();
var http = require('http').Server(app);
var mongo = require('mongodb');
var shell = require('shelljs');
var externalip = require('externalip');
const { spawn } = require('child_process');


var db;
var IP;
var port = process.env.PORT || 2000;
var mongoUrl = "mongodb+srv://admin:admin@chatupdb-5ios3.gcp.mongodb.net/test?retryWrites=true";
var servers = [];
var freeLoad = 0;

//Ανοίγουμε σύνδεση με τη βάση η οποία μένει ανοιχτή για μελλοντικές κλήσεις
mongo.connect(mongoUrl, { useNewUrlParser: true }, function (err, client) {
	if (err) throw err;

	db = client.db('ChatUp');

	//Παίρνουμε την ip του load balancer  
	externalip(function (err, ip) {

		IP = ip;
		var query = { loadbalancer: "true" }
		var newQuery = { $set: { ip: IP + ":" + port } };
		//κάνουμε update τη βάση με την ip που πήραμε και τρέχουμε την function για να δούμε την τρέχουσα κατάσταση
		db.collection("loadbalancer").updateOne(query, newQuery, function (err, res) {
			if (err) throw err;
			CheckServerAvailability();
		});
	});
});


http.listen(port, function () {
	console.log("listening on :" + port);
});


app.get('/', function (req, res) {

	//Ανακατεύθηνση client στον εκάστοτε επιλεγμένο server (πρώτος στον πίνακα)
	console.log("Current server: " + servers[0].ip);
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.redirect("http://" + servers[0].ip);

});

//'Ελεγχος τρέχουσας κατάστασης συτήματος και servers
app.get('/ServerUpdate', function (req, res) { 
	CheckServerAvailability();
	res.end();
});

function CheckServerAvailability() {
	freeLoad = 0;

	// παίρνουμε από τη βάση όλες τις πληροφορίες που έχουμε για τους ενεργούς servers
	db.collection('servers').find({}).toArray(function (err, result) {
		if (err) throw err;
		if (result != null) {
			servers = result;
		}
		//βάζουμε σε έναν πίνακα τα objects και τους στοιχίζουμε από τον πιο άδειο στον πιο γεμάτο
		servers.sort(function (a, b) { return b.load - a.load });

		//όταν κάποιος server φτάσει στο 80% του συνολικού του ορίου τον βγάζουμε από τον πίνακα
		for (var i = 0; i < servers.length; i++) {
			if (servers[i].load >= 80) {
				servers.shift();
				i--;
				continue;
			}

			freeLoad = freeLoad + (80 - servers[i].load);
		}

		//αν η υπολοιπόμενη χωριτηκότητα είναι λιγότερη από 50% δημιουργείται νέο instance 
		if (freeLoad < 50) {
			CreateNewServer();
		}

		console.log(servers);

	});
}

// δημιουργία νέου instance μέσω api του Google Cloud 
function CreateNewServer() {

	const run = spawn('sh', ['/home/dodina96/ChatUp/snap.sh']);
	run.on('close', (code) => {
		console.log('child process exited with code' + code);
	});

}
