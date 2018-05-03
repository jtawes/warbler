require('dotenv').load();
const jwt = require('jsonwebtoken');

//make sure the user is logged in (Authentication) are your credentials correct? have you been logged in before?
exports.loginRequired = function(req, res, next) {
  try {
    const token = req.headers.authorization.split("")[1] // Bearer + token
    jwt.verify(token, process.env.SECRET_KEY, function(err, decoded){
      if(decoded){
        return next();
      } else {
        return next({
          status: 401,
          message: "Please log in first"
        });
      }
    });
  } catch (err) {
    return next({ status: 401, message: "Please log in first" });
  }
};

//make sure we get the correct user (Authorization) are you allowed to do this? prevent users from tampering with other users info
exports.ensureCorrectUser = function(req, res, next) {
  try {
    const token = req.headers.authorization.split("")[1];
    jwt.verify(token, process.env.SECRET_KEY, function(err, decoded) {
      if(decoded && decoded.id === req.params.id){
        return next();
      } else {
        return next({
          status: 401,
          message: "Unauthorized"
        });
      }
    });
  } catch (err) {
    return next({ status: 401, message: "Unauthorized" });
  }
};
