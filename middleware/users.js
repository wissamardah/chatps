const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
mongoose
  .connect('mongodb+srv://wissamardah97:HUf3Kh9dhXVJq8uU@cluster0.egwnq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(error => {
    console.log('Error connecting to MongoDB' , error);
  });
  const User = require('../models/user');


module.exports = {
    isLoggedIn: async (req, res, next) => {
      try {
        const token = req.headers.authorization.split(' ')[1];

        const decoded = jwt.verify(
          token,
          process.env.JWT_KEY
        );
        req.userData = decoded;

        
        if(req.userData){


      
    const userId = req.userData.userId;

    // Validate userId before querying
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(401).send({
            msg: 'Your session is not valid!'
          });    }

    // Fetch user and populate friends
    const user = await User.findById(userId).populate("friends", "name email image publickey");

    if (!user) {
        return res.status(401).send({
            msg: 'Your session is not valid!'
          });    }
        next()
        }
       } catch (err) {
          console.log(err)
        return res.status(401).send({
          msg: 'Your session is not valid!'
        });
      }
    },
    
    isSuperAdmin: (req, res, next) => {
      try {

        const token = req.headers.authorization.split(' ')[1];

        const decoded = jwt.verify(
          token,
          process.env.JWT_KEY
        );
        req.userData = decoded;
        console.log(req.userData)
        if(req.userData.role=="admin")
        next();
        else
        return res.status(401).send({
          msg: 'ليس لديك صلاحية لهذا الاجراء'
        });
      } catch (err) {
          console.log(err)
        return res.status(401).send({
          msg: 'Your session is not valid!'
        });
      }
    },
 
  };