const express    = require('express');
const bodyParser = require('body-parser');
const bcrypt     = require('bcryptjs');
const sessions   = require('client-sessions');
const mongoose   = require('mongoose');
const csurf      = require('csurf');
const helmet     = require('helmet');

const app = express();
app.set('view engine', 'ejs');


// Database
///////////////////////////////////////////

const url = process.env.DB_URL ? process.env.DB_URL : require('./config/creds').url;

mongoose.connect(url, { useNewUrlParser: true });

let User = mongoose.model('User', new mongoose.Schema({
  email:     { type: String, required: true, unique: true},
  nickname:  { type: String, required: true},
  password : { type: String, required: true}
}));


// Middlewares
//////////////////////////////////////////////

app.use('/public', express.static('public'));

function verifyPassword (req, res, next) {
  if ( req.body.password && req.body.password.length<8 ) {
    var error = { error: "Please use a password with 8 characters or more."};
    return res.render("register", error);
  }
  next();
}

function verifyInput(req, res, next){
  if ( (req.body.nickname && /[<>'%]/.test(req.body.nickname)) ||
       (req.body.email && /[<>'%]/.test(req.body.email))       || 
       (req.body.password && /[<>'%]/.test(req.body.password)) ){
    var error = { error: "<>'% characters not allowed!"};
    return req.body.nickname ? res.render("register", error) : res.render("login", error);
  }
  next();
}

function verifyOrigin(req, res, next){
  if ( !(/Firefox/.test(req.headers['user-agent']) ||
         /Chrome/.test(req.headers['user-agent'])  ||
         /Safari/.test(req.headers['user-agent'])) ){
    return res.render("badOrigin.ejs");
  }
  next();
}

function verifySession(req, res, next){
  
  if (!(req.session && req.session.userId)){
    return next();
  }

  User.findById(req.session.userId, (err, user) =>{
    if (err) {
      return next(err);
    }

    if (!user) {
      return next();
    }
    
    user.password = undefined;

    req.user = user;
    res.locals.user = user;

    next();
  });
}

function loginRequired(req, res, next){
  if (!req.user) {
    return res.redirect("/login");
  }
  next();
}

app.use(verifyOrigin);

app.use(bodyParser.urlencoded({
  extended: false
}));


app.use(sessions({
  cookieName : "session",
  secret : process.env.SECRET ? process.env.SECRET : require('./config/creds').secret,  
  duration : 30 * 60 * 1000,     
  activeDuration : 5 * 60 * 1000,
  httpOnly: true,
  secure: true,
  ephemeral: true
}));


// CSRF protection middleware
////////////////////////////////////////////


var csrfProtection = csurf();


// http headers security protection middleware
/////////////////////////////////////////////


app.use(helmet());


// Routes
//////////////////////////////////////////////////


app.get('/', function(req,res){
  if (!req.session.userId) {
    return res.render('index.ejs');
  }
  res.redirect("/dashboard");
});

app.get('/login', csrfProtection, function(req,res){
  res.render('login.ejs', { csrfToken: req.csrfToken() });
});

app.get('/register', csrfProtection, function(req,res){
  res.render('register.ejs', { csrfToken: req.csrfToken() });
});

app.get('/dashboard', verifySession, csrfProtection, loginRequired, (req, res) => {
  res.render('dashboard', { nickname : req.user.nickname }); 
});

app.get('*', function(req,res){
  res.render('404.ejs');
});


// Login & register routes
/////////////////////////////////////////////////////


app.post('/register', verifyInput, verifyPassword, function(req,res){
  let hash = bcrypt.hashSync(req.body.password, 14);
  req.body.password = hash;
  let user = new User(req.body);

  user.save((err) => {
    if (err){
      let error = "Something bad happened! Please try again.";
      if (err.code === 11000){
        error = "That email is already registered!"
      }
      return res.render('register', { error: error});
    }

    res.redirect("/login");
  });
});



app.post('/login', verifyInput, (req,res) => {

  User.findOne({ email: req.body.email }, (err, user) => {
    if (err || !user || !bcrypt.compareSync(req.body.password, user.password)){
      return res.render("login", { error: "Incorrect email/password."});
    }
   
    
    req.session.userId = user._id;
    //console.log(req.session);
    res.redirect("/dashboard");
  });
});


// Server
////////////////////////////////////////////

const port = process.env.PORT || 3000;
var server = app.listen(port, listening);

function listening(){
  console.log('listening...');
}


