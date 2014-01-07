/**
 * Module dependencies.
 */

var express = require('express'),
  expressValidator = require('express-validator'),
  http = require('http'),
  fs = require("fs"),
  path = require('path'),
  crypto = require('crypto'),
  mysql = require("mysql"),
  config = require("./config.json");


var logFile = fs.createWriteStream("./log", {flags: "a"});

var app = express();
app.configure(function(){
  app.set('port', process.env.PORT || config.app.port);
  app.use(express.favicon());
  app.use(express.logger({stream: logFile}));
  app.use(express.bodyParser());
  app.use(expressValidator());
  app.use(express.methodOverride());
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});

var cipherSecret = config.app.token_secret;

function getCipher() {
  return crypto.createCipher("aes256", cipherSecret);
}
function getDecipher() {
  return crypto.createDecipher("aes256", cipherSecret);
}

var sessionUser;

var db = mysql.createConnection({
  user: config.database.user,
  password: config.database.password,
  host: config.database.host,
  database: config.database.name
});
db.connect(function (err) {
  if (err)
    throw err;
});

function generateToken(salt) {
  var token = Math.round((new Date().valueOf() * Math.random()))
              + ":" + salt +":" + new Date().getTime();
  var cipher = getCipher();
  return cipher.update(token, "utf8", "hex") + cipher.final("hex");
};

// check the token from request header
function checkAuth(req, res, next) {
  var token = req.headers.token;
  if (!token) {
    return _unauthorized(res, "token missing");
  }
  try {
    var decipher = getDecipher();
    token = decipher.update(token, "hex", "utf8") + decipher.final("utf8");
    token = token.split(":");
  } catch (e) {
    console.error(e);
    return _unauthorized(res, "invalid token");
  }
  // check if token hasn't expired (1 hour)
  var now = new Date().getTime();
  if (now - token[3] > 3600000) {
    return _unauthorized(res, "token expired");
  }
  // verify user in db
  db.query("SELECT id, username"
            + " FROM users"
            + " WHERE password = ? AND salt = ?",
            [token[1], token[2]], function(err, result, fields) {
    if (err) {
      return _internal("error in db query", err);
    }
    sessionUser = result[0];
    if (sessionUser) {
      next();
    } else {
      _unauthorized(res, "user unknown");
    }
  });
};

function _badrequest(res, message) {
  var obj = {error: "bad request"};
  if (message) {
    obj.message = message;
  }
  res.json(400, obj);
};
function _unauthorized(res, message) {
  // TODO:: log error
  var obj = {error: "unauthorized"};
  if(message) {
    obj.message = String(message);
  }
  res.json(401, obj);
};
function _internal(res, message, error) {
  // TODO: log error
  var obj = {error: "internal server error"};
  if(message) {
    obj.message = String(message);
  }
  res.json(500, obj);
};


app.get('/', function (req, res) {
  fs.readFile(__dirname + "/public/index.html", "utf8", function (err, text) {
    res.send(text);
  })
});

app.post("/login", function (req, res) {
  if (!req.body.username || !req.body.password) {
    return _unauthorized(res, "credentials missing");
  }

  db.query("SELECT id, username, password, salt"
            + " FROM users"
            + " WHERE username = ? LIMIT 1",
            [req.body.username], function (err, result, fields) {
    if(err) {
      _internal(res, err);
    }
    // encrypt given password
    result = result[0];
    var pw = req.body.password;
    var encpw = crypto.createHmac("sha1", result.salt).update(pw).digest("hex");    
    if (encpw !== result.password) {
      return _unauthorized(res);
    }
    // generate login token
    var token = generateToken(result.password + ":" + result.salt);

    res.json({
      id: result.id,
      name: result.username,
      token: token
    });
  });
});

app.post("logout", function(req, res) {

});

// list users
app.get('/user', checkAuth, function (req, res) {
  db.query("SELECT id, username"
            + " FROM users",
            [], function (err, result, fields) {
    if (err) {
      _internal(res, err);
    }
    // send complete result without modification
    res.json(result);
  })
});

// create new user
app.post('/user', checkAuth, function (req, res) {

  // validate input
  req.assert("username", "username missing").notEmpty();
  req.assert("username", "wrong format").is(/[a-zA-Z0-9]{3,32}/);
  req.assert("password", "password missing").notEmpty();
  req.assert("password", "wrong format").is(/^.{6,32}$/);
  var err = req.validationErrors();
  if (err) {
    return _badrequest(res, err);
  }
  
  var username = String(req.body.username),
      password = String(req.body.password);
  // generate salt
  var salt = Math.round(new Date().valueOf()) + "";
  var encpw = crypto.createHmac("sha1", salt).update(password).digest("hex");
  db.query("INSERT INTO users (`username`, `password`, `salt`)"
            + " VALUES (?,?,?)",
            [username, encpw, salt], function(err, result, fields) {
    if (err) {
      // also used for duplicate entries - not so nice
      return _internal(res, err);
    } else {
      res.json({
        id: result.insertId,
        username: username
      });
    }
  });

});

// start app
http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
});
