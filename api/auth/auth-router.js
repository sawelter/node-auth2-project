const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../users/users-model')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { username, password } = req.body;
    const role_name = req.role_name;

    const hash = bcrypt.hashSync(password);
    const newUser = { username, password: hash, role_name};
    const result = await User.add(newUser);
    res.status(201).json(result);
  } catch(err) {
    next(err);
  }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

    const { username, password } = req.body;

    User.findBy({ username })
      .then(user => {
        if(user && bcrypt.compareSync(password, user.password)) {
          const token = buildToken(user);
          res.status(200).json({message: `${username} is back!`, token: token});
        } else {
          res.status(401).json({message: "Invalid credentials"})
        }
      })
      .catch(next);
});



/* helper function buildToken (user)
	payload = subject (id), username, role
	options = exp date of token (expiresIn)
	return jwt.sign(payload, [secret string!], options)
*/

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
