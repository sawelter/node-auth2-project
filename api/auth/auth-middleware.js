const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model');
const jwt = require('jsonwebtoken');


  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if(token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if(err) {
        res.status(401).json({ message: "Token invalid "});
      } else {
        req.decodedJwt = decoded;
        next();
      }
    })
  } else {
    res.status(401).json({ message: "Token required" });
  }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 console.log("role name: ", role_name)
 console.log("req.decoded", req.decoded)
  if(req.decodedJwt && req.decodedJwt.role_name === role_name) {
    next();
  } else {
    res.status(403).json({
      message: "This is not for you"
    })
  }
}

// student token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0Ijo2LCJ1c2VybmFtZSI6InNhd3llcmEiLCJyb2xlX25hbWUiOiJzdHVkZW50IiwiaWF0IjoxNjgyOTYxNzQxLCJleHAiOjE2ODMwNDgxNDF9.Rk-z6x9fUv1pRnXrabYOmkhcdit1nuXsylo-o7Q6S3U

// admin token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0IjoxLCJ1c2VybmFtZSI6ImJvYiIsInJvbGVfbmFtZSI6ImFkbWluIiwiaWF0IjoxNjgyOTYxNzgxLCJleHAiOjE2ODMwNDgxODF9.20YOwGtQneTreE46iqt2TljS8UWLFMZ7kRbmFlaDI24


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */

  try {
    const { username } = req.body;
    const user = await User.findBy({ username });
    if(user) {
      next();
    } else {
      res.status(401).json({message: "Invalid credentials"});
    }
  } catch(err){
    next(err);
  }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  let { role_name } = req.body;
  if (role_name) {
    role_name = role_name.trim();
  }

  if (!role_name) {                        // OK
    req.role_name = 'student';
    next();
  } else if (role_name === 'admin') {      // OK
    next({ status: 422, message: "Role name can not be admin" })
  } else if (role_name.length > 32) {      // OK
    next({ status: 422, message: "Role name can not be longer than 32 chars" })
  } else {                                // OK
    req.role_name = role_name;
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
