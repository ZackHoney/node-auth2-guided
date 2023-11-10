const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../../config')

// AUTHENTICATION
const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({status: 401, message: 'bad token'})
      } else {
        req.decodedJwt = decoded
      }
    })
  } else {
    next({ status: 401, message: 'What!?!?!?! No token?'})
  }
}

// AUTHORIZATION
const checkRole = role => (req, res, next) => {
  if(req.decodedJwt && req.decodedJwt.role === role ){
    next()
  } else {
    next({ status: 403, message: 'not authorized'})
  }
}

module.exports = {
  restricted,
  checkRole,
}
