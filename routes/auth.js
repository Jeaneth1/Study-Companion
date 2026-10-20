const express = require('express');
const { rateLimit } = require('express-rate-limit');
const router = express.Router();
const bcrypt = require('bcryptjs');
/* go to one folder is ..*/
const db = require('../db');

router.get('/signup', (req, res)=>{
res.render('signup');
});

router.post('/signup', (req, res)=> {
const {username, email, password} = req.body;

if (password.length < 8){
    return res.status(400).send('Password must be at least 8 characters long');

}const hasSpecialChar = /[!@#$%^&*au(),.?":{}|<>]/.test(password);
if (!hasSpecialChar) {
    return res.status(400).send('Password must include at least one special character');
}
const hashedPassword= bcrypt.hashSync(password,10);


try{
const insert =db.prepare('INSERT INTO users (username,email, password) VALUES(?,?,?)');
insert.run(username, email, hashedPassword);
res.redirect('/signin');
    }catch (err){
res.status(400).send('Signup failed '+ err.message);
    }
});

router.get('/signin',(req, res)=>{
res.render('signin');
});

const signinLimiter = rateLimit({
    // what our time limit is 10 mins and 6000 one min in milliseconds
    windowMs: 10 * 60* 1000,
    limit: 5,
    message: 'You have reached the sign-in attempt limit. Try again in 10 minutes.',

});

router.post('/signin', signinLimiter, (req, res) => {
    
const {username, password} = req.body;
const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);

if (!user){
console.log('Signin failed: username not found');
return res.status(401).send('Invalid username or password');
    }

const passwordMatches = bcrypt.compareSync(password, user.password);

if (!passwordMatches){
console.log('Signin failed: wrong password');
return res.status(401).send('Invalid username or password');
    }

req.session.regenerate(function(err) {
if (err) {
console.log('Session regenerate failed:', err.message);
return res.status(500).send('Something went wrong signing in');
        }
req.session.userId = user.id;
res.redirect('/');
    });

});

module.exports= router;