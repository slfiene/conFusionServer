var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');
var Dishes = require('./models/dishes');

var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var GitHubTokenStrategy = require('passport-github-token');

var config = require('./config');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey, {
        expiresIn: 3600
    });
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));

exports.verifyUser = passport.authenticate('jwt', {session: false});

exports.verifyAdmin = (req, res, next) => {
    if (req.user.admin) {
        next();
    } else {
        var err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
    }
}

exports.verifyIsAuthor = (req, res, next) => {
    Dishes.findById(req.params.dishId)
    .populate('comments.author')
        .then((dish) => dish.comments.id(req.params.commentId))
        .then((comment) => {
            if (req.user._id.equals(comment.author._id)) {
                next();
            } else {
                var err = new Error('You are not the author of this comment!');
                err.status = 403;
                return next(err);
            }
        })
        .catch(err => next(err));
}

exports.GitHubTokenStrategy = passport.use(new GitHubTokenStrategy({
    clientID: config.github.clientId,
    clientSecret: config.github.clientSecret
}, (accessToken, refreshToken, profile, done) => {
    User.findOne({githubId: profile.id}, (err, user) => {
        if (err) {
            return done(err, false);
        }
        if (!err && user !== null) {
            return done(null, user)
        }
        else {
            user = new User({ 
                username: profile.displayName});
                user.githubId = profile.id;
                user.firstname = profile.name.givenName;
                user.lastname = profile.name.familyName;
                user.save((err, user) =>
                {
                    if (err) 
                    return done(err, false);
                    else
                    return done(null, user);
                })
        }
    })
}

))