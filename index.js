var express = require('express');
var app = express();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var bodyParser = require('body-parser');
var session = require('express-session');
var path = require('path');
var mongo = require('mongodb');
var request = require('request');
var ObjectId = require('mongodb').ObjectId;
var shell = require('shelljs');
var externalip = require('externalip');
var crypto = require('crypto');

var port = process.env.PORT || 1337;

//Body-Parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'dodo' }));
app.use(express.json());

var IP;
var db;
var serverUserLimit = 10;
var serverLoad = 0;
var mongoUrl = "mongodb+srv://admin:admin@chatupdb-5ios3.gcp.mongodb.net/test?retryWrites=true";
var timer = null;
var loadbalancer;

//Ανοιγουμε συνδεση με τη βαση η οποια μενει ανοιχτη για μελλοντικες κλησεις στη βαση
mongo.connect(mongoUrl, { useNewUrlParser: true }, function (err, client) {
	if (err) throw err;

	db = client.db('ChatUp');

	// Βρίσκουμε την ip του server
	externalip(function (err, ip) {
		IP = ip;

		// Παίρνουμε από τη βάση την ip του Load Balancer
		var query = { loadbalancer: "true" };

		db.collection('loadbalancer').findOne(query, function (err, result) {
			if (err) throw err;

			loadbalancer = "http://" + result.ip;

			query = { 'ip': IP + ":" + port }

			//Αν η ip του server υπάρχει ήδη μηδενίζουμε το load του στη βάση 
			db.collection('servers').find(query).toArray(function (err, result) {
				if (err) throw err;

				if (result.length > 0) {

					query = { 'ip': IP + ":" + port };
					var newValues = { $set: { load: 0 } };

					db.collection("servers").updateOne(query, newValues, function (err, result1) {
						if (err) throw err;

						request.get(loadbalancer + "/ServerUpdate");
					});

				} else { //αλλιώς προσθέτουμε νέα εγγραφή

					query = { "ip": IP + ":" + port, "load": 0 }

					db.collection("servers").insertOne(query, function (err, result) {
						if (err) throw err;

						request.get(loadbalancer + "/ServerUpdate");

					});
				}
			});
		});
	});

	ShutDownClock();

});

http.listen(port, function () {
	console.log("listening on :" + port);
});

// κλήση στο βασικό url
app.get('/', function (req, res) {

	// Αν δεν υπάρχει username ή ip στο session μετάβαση στο Login page
	if (!req.session.userName) {

		res.sendFile(path.join(__dirname + '/Login.html'));

	} else {
		//Αλλιως μετάβαση στο περιβάλλον της εφαρμογής
		res.redirect("/UI");
	}

});

app.get('/UI', function (req, res) {

	// Αν δεν υπάρχει username στο session μετάβαση στο βασικό url
	if (!req.session.userName) {
		res.redirect("/");
	} else {
		//Αλλιως φόρτωση html σελίδας με το βασικό UI
		res.sendFile(path.join(__dirname + '/UI.html'));

	}
});

app.get('/UI/GetUserInfo', function (req, res) {

	if (req.session.userName) {
		LoadChats(req.session.userName, res); //μέθοδος για αποστολή ιστορικού συνομιλιών στον client 
	} else {
		res.send("error");
		res.end();
	}
});

app.get('/Register', function (req, res) {
	//μετάβαση στην html σελίδα για την εγγραφή χρήστη
	res.sendFile(path.join(__dirname + '/Register.html'));
});

app.get('/Logout', function (req, res) {
	//μετάβαση στο αρχικό url (login page) σβήνοντας το session username (και αυτόματη αποσύνδεση sockets)
	req.session.userName = null;
	res.redirect('/');
});


app.post('/Login', function (req, res) {
	// Μόλις γίνει Login κάνουμε τις απαραίτητες μετατροπές και αποθηκεύουμε σε έναν πίνακα το username και το password που παίρνουμε από τον client
	var clientIP = JSON.stringify(req.body);
	clientIP = clientIP.split(":");
	var flag = false;

	//Ελέγχουμε πόση ώρα είναι στο Login page ο χρήστης με το αν είναι μέσα στην λίστα
	for (var i = 0; i < visitorsArray.length; i++) {
		if (visitorsArray[i] == clientIP[2]) {
			flag = true;
			break;
		}
	}

	//Αφού αφαιρεθεί ο visitor γίνεται ταυτοποίηση και login
	if (flag == true) {
		var username = JSON.stringify(req.body);
		username = username.split("\"");
		username = username[1].split(":");

		//Κλήση στη βάση και εύρεση του χρήστη με τα παραπάνω στοιχεία
		var query = { 'username': username[0] }
		db.collection('users').findOne(query, function (err, result) {
			if (err) throw err;
			if (result != null) {
				salt = result.password.slice(0, 16);
				var checker = saltHashPassword(username[1], salt);
				if (checker == result.password) {
					//Αν βρεθεί ο χρήστης βάζουμε στο session το username 
					req.session.userName = username[0];
					//βάζουμε στη βάση στον χρήστη την διαθέσιμη IP του server που τον εξυπηρετεί
					query = { 'username': result.username }
					var newValues = { $set: { ip: IP + ":" + port } };
					db.collection("users").updateOne(query, newValues, function (err, result1) {
						if (err) throw err;

					});

					// Κάθε φόρα που μπαίνει νέος χρήστης το ρολόι που μετράει αντίστροφα 
					//για μία ώρα ώστε να κλέισει ο server μηδενίζεται και μετράει από την αρχή
					if (timer) {
						clearTimeout(timer);
						timer = null;
						ShutDownClock();
					}

					//Εφόσον γίνει login αφαιρούμε από την λίστα την ip του client και παύει να θεωρείται "visitor"
					RemoveVisitor(clientIP[2]);

					res.send("ok");

				} else {
					res.send("error");
				}
			} else {
				res.send("error");
			}

		});
	} else {
		res.send("error refresh");
	}

});

// Όταν πάει να γίνει εγγραφή νέου χρήστη ελέγχονται ο κωδικός και το username αν είναι αποδεκτά από το σύστημα 
app.post('/Register', function (req, res) {

	var credentials = JSON.stringify(req.body);
	credentials = credentials.split("\"");
	credentials = credentials[1].split(":");
	var flag;

	if (credentials[0].length < 4 || credentials[0].includes(" ", ":", "\"")) {
		res.send("usernameError");
		flag = false;
	}


	//Αν περάσει τους πρώτους ελέγχους παράγει τυχαίο string χαρακτήρων (salt) και το μετατρέπει σε δεκαεξαδικό 
	if (flag != false) {
		if (credentials[0] != "" && credentials[1] != "") {
			var salt = crypto.randomBytes(Math.ceil(16 / 2)).toString('hex').slice(0, 16);
			//βάζουμε hash στον κωδικό και πρσθέτουμε το salt
			var hashedPwd = saltHashPassword(credentials[1], salt);

			// Bάζουμε τις πληροφορίες από τη σελίδα σε ένα object
			var newUser = {
				username: credentials[0],
				password: hashedPwd,
				ip: ""
			};
			flag = true;
		} else {
			res.send("inputError");
		}
	}
	if (flag == true) {
		// Αν περάσουμε από τους προηγούμενους ελέγχους κοιτάμε αν στη βάση υπάρχει ήδη χρήστης με αυτά τα στοιχεία
		db.collection('users').findOne({ "username": newUser.username }, function (err, result) {
			if (err) throw err;

			if (result) {
				//Αν ναι γυρνάμε στην σελίδα εγγραφής
				res.send("DBerror");

			} else {
				//Αλλιώς αποθηκεύουμε στη βάση τον νέο χρήστη και κάνουμε redirect στο UI
				db.collection('users').insertOne(newUser, function (err, result) {
					if (err) throw err;
				});
				res.send("ok");
			}
		});
	}
});

app.post('/CatchMessage', function (req, res) {
	//Όταν έρχεται post από άλλον server για παράδοση μηνύματος 
	for (var q = 0; q < req.body.receivers.length; q++) {
		for (var i = 0; i < users.length; i++) { //ψάχνουμε τον παραλλήπτη στον πίνακα και το μήνυμα φτάνει σε αυτόν μέσω sockets
			if (req.body.receivers[q] == users[i]) {
				for (var j = 0; j < sockets[i].length; j++) {
					io.to(sockets[i][j]).emit('message received', { "message": req.body.message, "receivers": req.body.receivers.toString(), "id": req.body.id });
				}
			}
			break;

		}
	}
	res.end();
});

// Όταν κάποιος μπαίνει στο Login page στέλνεται εδώ η IP του και την αποθηκεύουμε σε έναν πίνακα μέχρι να κάνει login
app.post("/SetTimerVisitors", function (req, res) {
	var visitorIP = JSON.stringify(req.body);
	visitorIP = visitorIP.split("\"");
	visitorsArray.push(visitorIP[1]);
	//Βάζουμε σε μια ώρα να τρέξει μια function που αφαιρεί την IP από τον πίνακα ώστε να χρειαστεί ο χρήστης να κάνει refresh και να μην του επιτραπεί η πρόσβαση 
	var visitorTimer = setTimeout(RemoveVisitor, 420000, visitorIP[1]);
	//η μεταβλητή που μετράει αντίστροφα για να τρέξει η function για έναν συγκεκριμμένο χρήστη μπαίνει στον δυσδιάστατο πίνακα δίπλα στην IP
	visitorsArray[0].push(visitorTimer);
});


var users = [];
var sockets = [];
var visitorsArray = [];
visitorsArray.push([]);


// Όταν συνδέεται ενα socket
io.on('connection', function (socket) {

	//Στέλνεται το username του συνδεδεμένου χρήστη στον server 
	socket.on('username', function (msg) {
		socket.username = msg;

		var found = false;
		//Ψάχνουμε το username στον πίνακα με τους χρήστες
		for (var i = 0; i < users.length; i++) {
			//αν βρεθεί αποθηκεύεται στο socket του παράλληλα με το username του που είναι σε άλλο πίνακα
			if (users[i] === msg) {
				sockets[i].push(socket.id);
				found = true;
				break;
			}
		}

		//Αν το username δεν είναι στον πίνακα (πρώτη σύνδεση) 
		if (!found) {
			users.push(msg); //βάζουμε στον πίνακα το username
			sockets.push([]);
			sockets[users.length - 1].push(socket.id); // και στον άλλο πίνακα το socket της σύνδεσης του
			socket.usr = msg; //μεταβλητή αντικειμένου socket με το username

			//Ενημερώνεται η βάση (ip) για το ποιος Server εξυπηρετεί τον χρήστη
			var query = { 'username': msg }
			var newValues = { $set: { ip: IP + ":" + port } };
			db.collection("users").updateOne(query, newValues, function (err, result1) {
				if (err) throw err;
			});
			UpdateServerLoad(); //Έλεγχος φόρτου για τυχόν ενημέρωση βάσης
		}

		console.log("A user connected: " + users[users.length - 1] + " Total users:" + users.length);
	});

	//Κατά την αποσύνδεση ενός socket σβήνουμε από τον πίνακα με τα sockets εκείνο του χρήστη που αποσυνδέθηκε και το username του
	socket.on('disconnect', function () {

		var tempUser = "";
		for (var i = 0; i < users.length; i++) {
			if (users[i] === socket.username) {
				for (var j = 0; j < sockets[i].length; j++) {
					if (sockets[i][j] === socket.id) {
						tempUser = sockets[i][j];
						sockets[i].splice(j, 1);
						if (sockets[i].length === 0) {
							users.splice(i, 1);
							sockets.splice(i, 1);
						}
						break;
					}
				}
				break;
			}
		}

		//σβήνουμε την συνδεδεμένη ip από την βάση
		var query = { 'username': socket.username }
		var newValues = { $set: { ip: "" } };
		db.collection("users").updateOne(query, newValues, function (err, result1) {
			if (err) throw err;
		});
		UpdateServerLoad(); //Έλεγχος φόρτου για τυχόν ενημέρωση βάσης
		session.userName = null;

		console.log("socket " + tempUser + " of user " + socket.username + " disconnected Total users:" + users.length);
	});

	//όταν κάποιος στέλνει μήνυμα 
	socket.on('message sent', function (msg) {
		msg.sender = socket.username;
		msg.receiver = msg.to;
		StoreMessage(msg, socket, function (msg, socket) { //αποθήκευση μηνυμάτων στη βάση στο ιστορικό
			ForwardMessages(msg, socket); //αποστολή μηνύματος
		});
	});
});


function StoreMessage(msg, socket, callback) { //Μέθοδος για αποθήκευση μηνυμάτων στη βάση στο ιστορικό

	var query;
	if (msg.id) {
		// Αν υπάρχει η collection με όνομα το id (στέλνεται από τον client) βάζουμε το μήνυμα στη βάση στο ιστορικό
		query = { "user": msg.sender, "message": msg.message }

		db.collection(msg.id).insertOne(query, function (err, result) {
			if (err) throw err;
			callback(msg, socket); //καλούμε τη ForwardMessages για να σταλεί το μήνυμα

		});
	} else {  //αν η collection δεν υπαρχει

		//παίρνουμε τους παραλήπτες που στέλνονται από τον client 
		var chatParticipants = msg.to.split(",");
		chatParticipants.push(msg.sender); // βάζουμε στους συμμετέχοντες τον αποστολέα
		var flag;

		//σχηματίζουμε ένα query για να βρούμε τους χρήστες της συνομιλίας στη βάση
		query = "[";
		for (var i = 0; i < chatParticipants.length - 1; i++) {
			query = query + "{\"username\": \"" + chatParticipants[i] + "\"},";
		}
		query = query + "{\"username\": \"" + chatParticipants[chatParticipants.length - 1] + "\"";
		query = query + "}]";
		query = JSON.parse(query);
		query = { $or: query }
		db.collection('users').find(query).toArray(function (err, result) {
			if (err) throw err;

			if (result.length == chatParticipants.length) {

				//Δημιουργούμε στη βάση την συνομιλία στο historyLogs
				var query = { "users": chatParticipants, "userCount": chatParticipants.length }
				db.collection('historyLogs').insertOne(query, function (err, result) {
					if (err) throw err;
					//Στέλνουμε στο frontend το όνομα της συνομιλίας για να εμφανιστεί στη σελίδα
					msg.id = result.insertedId.toString();
					var info = { "users": msg.to, "id": msg.id }
					io.to(socket.id).emit('newChatSender', info);

					//Φτιάχνουμε νεα collection στη βάση με όνομα το id απο το historyLogs και βάζουμε το πρώτο μήνυμα
					query = { "user": msg.sender, "message": msg.message }
					db.collection(msg.id).insertOne(query, function (err, result1) {
						if (err) throw err;

						//αποστολή μηνύματος στους παραλήπτες
						callback(msg, socket);
						return flag;
					});
				});
			} else {
				io.to(socket.id).emit('error');
				return flag;
			}
		});
	}
}


function LoadChats(user, response) { // Μέθοδος που ψάχνει στη βάση όλες τις συνομιλίες ενός χρήστη 
	var Chats = [];
	var Ids = [];

	var query = { "users": { $all: [user] } }

	db.collection('historyLogs').find(query).toArray(function (err, result) {
		if (err) throw err;
		if (result != null) { //αν βρεθούν βάζουμε σε πίνακες τις συνομιλίες και τα id τους
			for (var i = 0; i < result.length; i++) {
				Chats.push(result[i].users.toString());
				Ids.push(result[i]._id);
			}

			info = { "username": user, "chats": Chats, "id": Ids } //στέλνουμε τις πληροφοριες στον client
			response.send(info);
			response.end();
		} else { // αν δεν βρεθούν αποτελέσματα στη βάση 
			info = { "username": user, "chats": Chats, "id": Ids } //στέλνουμε ότι πληροφορία έχουμε στον client
			response.send(info);
			response.end();
		}

	});


}

function ForwardMessages(msg, socket) { //Μέθοδος που προωθεί τα μηνύματα στους παραλήπτες
	var query = { "_id": new ObjectId(msg.id) }

	db.collection("historyLogs").findOne(query, function (err, result) { //βρίσκουμε την συνομιλία στο historyLogs στη βάση
		if (err) throw err;
		var receivers = result.users;
		var id = result._id;
		//παίρνουμε τις πληροφορίες ολων των χρηστών που συμμετέχουν στη συνομιλία 
		query = "[";
		for (var i = 0; i < result.users.length - 1; i++) {
			query = query + "{\"username\": \"" + result.users[i] + "\"},";
		}
		query = query + "{\"username\": \"" + result.users[result.users.length - 1] + "\"";
		query = query + "}]";
		query = JSON.parse(query);
		query = { $or: query }
		db.collection('users').find(query).toArray(function (err, result) {
			if (err) throw err;
			//κοιτάμε την ip που είναι συνδεδεδεμένος ο κάθε χρήστης
			for (var q = 0; q < result.length; q++) {
				//Αν είναι στην ίδια με εκείνη του αποστολέα το μήνυμα παραδίδεται μέσω sockets
				if (result[q].ip == (IP + ":" + port)) {
					for (var i = 0; i < users.length; i++) {
						if (result[q].username == users[i]) {
							for (var j = 0; j < sockets[i].length; j++) {
								io.to(sockets[i][j]).emit('message received', { "message": socket.username + ": " + msg.message, "receivers": receivers.toString(), "id": id });
							}
							break;
						}
					}
				} else { //Αν είναι σε άλλο server

					//κάνουμε post request στον server που βρίσκεται ο παραλήπτης και στέλνουμε ενα JSON με τις κατάλληλες πληροφοίες για να προωθήσει εκείνος το μήνυμα
					request.post("http://" + result[q].ip + "/CatchMessage", {
						json: { message: socket.username + ": " + msg.message, receiver: result[q].username, "receivers": receivers, "id": id }
					}, function (error, res, body) {
						if (error) {
							return;
						}
					})

				}
			}
		});
	});

}

function UpdateServerLoad() {
	//Κάθε φορά που αλλάζει ο αριθμός των χρηστών και η διαφοροροποίηση 
	//είναι πάνω ή κάτω απο 10% από πριν ενημερώνεται η βάση
	loadDifference = ((users.length * 100) / serverUserLimit) - serverLoad;
	if (Math.abs(loadDifference) >= 10) {
		serverLoad = (users.length * 100) / serverUserLimit;
		var myquery = { ip: IP + ":" + port };
		var newvalues = { $set: { load: serverLoad } };

		console.log("server load: " + serverLoad);

		//Αν το φορτίο γίνει μεγαλύτερο απο ή ίσο με 50% ή 80% τότε ενημερώνουμε τον load balancer
		if (serverLoad >= 50 || serverLoad >= 80 && loadDifference > 0) {
			request.get(loadbalancer + "/ServerUpdate");

		}
		

		db.collection("servers").updateOne(myquery, newvalues, function (err, res) {
			if (err) throw err;
		});
	}
}

function ShutDownClock() { // Μέθοδος που ξεκινάει ενα timer ώστε να τρέξει η function που κλείνει το vm λόγο μηδενικού ή μικρού φόρτου μετά από μια ώρα
	timer = setTimeout(ShutDownVm, 3600000);
}

function ShutDownVm() { // Μέθοδος που διαγράφει το vm η κάνει merge 2 servers
	if (serverLoad <= 20) {
		var query = {}
		var newIp;
		var minload = 100;
		// Ψάχνει στην βάση και κοιτάει όλους τους servers
		db.collection('servers').find(query).toArray(function (err, result) {
			if (err) throw err;
			if (result != null) {
				// αν υπάρχουν παραπάνω από έναν server (δεν είναι ο τελευταίος ανοιχτός)
				if (result.length > 1) {
					//και έχει συνδεδεμένους χρήστες
					if (users.length > 0) {
						// βρίσκει τον server με τους λιγότερους συνδεδεμένους χρήστες (μικρότερο load)
						for (var i = 0; i < result.length; i++) {
							if (result[i].ip != (IP + ":" + port)) {
								if (result[i].load < minload) {
									minload = result[i].load;
									newIp = result[i].ip;
								}
							}
						}
						// εαν γίνεται κάνει merge με τον server που έχει το μικρότερο φόρτο
						if (minload <= 50) {
							//τρέχει την μέθοδο που κάνει merge
							MergeServer(newIp);
						} else {
							//Αλλίως ελέγχουμε αν ο server είναι άδειος για να κλείσει ή αν πρέπει να παραμείνει ανοιχτός
							if (serverload > 0) {
								ShutDownClock();
								return;
							}
						}
					}

					//εάν γίνει το merge ή είναι άδειος και πρέπει να κλείσει, αφαιρεί τον εαυτό του από την βάση και κλείνει το vm
					query = { 'ip': IP + ":" + port }
					db.collection("servers").deleteOne(query, function (err, result) {
						if (err) throw err;
						console.log("Server is shutting down");
						request.get(loadbalancer + "/ServerUpdate");
						shell.exec('sh /home/dodina96/ChatUp/deleteVm.sh');

					});
				}
			}
		});
	} else {
		//Αν δεν ικανοποιείται καμία συνθήκη τότε ο χρόνος μηδενίζεται ώστε να ξαναγίνει όλη η διαδικασία σε μία ώρα 
		ShutDownClock();
	}
}


function MergeServer(newIp) {

	//Γίνεται  broadcast σε όλους τους συνδεδεμένους clinets να άλλαξουν server 
	io.emit("changeServer", newIp);

	//βρίσκουμε όλους τους χρήστες στον server που πρόκειται να σβηστεί 
	//και αλλάζουμε την IP τους σε εκείνη του καινούργιου
	for (var i = 0; i < users.length; i++) {
		var query = { 'username': users[i] }
		var newValues = { $set: { ip: newIp } };
		db.collection("users").updateOne(query, newValues, function (err, result) {
			if (err) throw err;

		});
	}
}


function saltHashPassword(userpassword, salt) {

	// βάζουμε hash στον κωδικό πρόσβασης με sha512.
	var sha512 = function (password, salt) {
		var hash = crypto.createHmac('sha512', salt);
		hash.update(password);
		var value = hash.digest('hex');
		return salt + ":" + value;
	};

	var passwordData = sha512(userpassword, salt);
	return passwordData;
}

function RemoveVisitor(visitorip) {
	//Αφαιρούμε την ip και το timer όσων ήταν στο Login page από την λίστα visitorsArray αφού συνδεθούν
	for (var i = 0; i < visitorsArray.length; i++) {
		if (visitorsArray[i] == visitorip) {
			visitorsArray[0].splice(i, 1);
			visitorsArray.splice(i, 1);
			break;
		}
	}

}
