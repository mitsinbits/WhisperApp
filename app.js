require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption')
//var md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')

const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require('mongoose-findorcreate')
const app = express();
app.use(express.static('public'))
app.set('view engine','ejs');

app.use(bodyParser.urlencoded({ extended: true}));

app.use(session({
    secret: 'ThisIsmySecret',
    resave: false,
    saveUninitialized: false,
  }))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userdb",{useNewUrlParser: true, useUnifiedTopology: true});

mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);





// var encKey = process.env.SOME_32BYTE_BASE64_STRING;
// var sigKey = process.env.SOME_64BYTE_BASE64_STRING;

//userSchema.plugin(encrypt, {secret: process.env.SECRET , excludeFromEncryption: ['email'] });

const User = mongoose.model('User',userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));



app.get('/',(req,res)=>{
    res.render("home");
})

app.get('/auth/google',
  passport.authenticate('google', { scope:
      ['profile' ] }
));

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

app.get('/register',(req,res)=>{
    res.render("register");
})

app.get('/login',(req,res)=>{
    res.render("login");
})

app.get("/secrets",(req,res) => {
    var isloggedIn = false;
    if(req.user){
        isloggedIn =true
    }
    User.find({"secret":{$ne:null}},(err,founduser) => {
        if(err){ console.log(err)}
        else{
            if(founduser){
                res.render("secrets",{userswithSecrets:founduser,login:isloggedIn})
            }
        }
    })
})

app.get("/submit",(req,res) => {
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
})

app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect('/');
})

app.post("/submit",(req,res)=>{
    const SubmittedSecret = req.body.secret;

    User.findById(req.user.id,(err,founduser)=>{
        if(err){ console.log(err)}
        else{
            if(founduser){
                founduser.secret = SubmittedSecret
                founduser.save((err)=>{
                    if(err){ console.log(err)}
                    else{
                        res.redirect("/secrets")
                    }
                })
            }
        }
    })

})

app.post('/register',(req,res)=>{
   
    User.register({username:req.body.username},req.body.password,(err,user) => {
        if(err){
            console.log(err);
            res.redirect("/register")
        }
        else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            })
        }
    })
})

app.post('/login',(req,res)=>{
    
    const user = new User({
        username:req.body.username,
        password:req.body.password
    })

    req.login(user, function(err) {
        if (err) { console.log(err)}
        else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            })
        }
      });
})

app.listen(3000,()=>{
    console.log("Connected to server 3000");
});