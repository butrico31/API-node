const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../Model/model");


const createUser = async (req, res) => {
    try {
        const user = new User({
            name: req.body.name,
            _id: req.body._id,
            email: req.body.email,
            password: await bcrypt.hash(req.body.password, 10),
            admin: false,
      });
  
      await user.save();
      return res.status(200).send(user);
    } catch (error) {
      return res.status(400).send(error);
    }
};

const loginUser = async (req, res) => {
    try{
        const login = new User({
            _id: req.body._id,
            password: req.body.password,
        });

        const jwtConfig = {
            expiresIn: '5d',
            algorithm: 'HS256',
        };

        const find = await User.findById(login._id);

        if(bcrypt.compare(find.password, login.password)){

            token = jwt.sign({data : find}, process.env.SECRET, jwtConfig);
            
            return res.status(200).send(token);
        }
        return res.status(401);
    }
    catch(error){
        return res.status(400).send(error);
    }
};



module.exports = {
    createUser,
    loginUser,
};