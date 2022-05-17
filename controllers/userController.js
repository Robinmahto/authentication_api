import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import transporter from "../config/emailConfig.js";

class UserController {
  // Registration
  static userRegistration = async (req, res) => {
    const { name, email, password, password_conformation, tc } = req.body;
    const user = await UserModel.findOne({ email: email });
    if (user) {
      res.send({ status: "failed", message: "Email already Exists" });
    } else {
      if (name && email && password && password_conformation && tc) {
        if (password == password_conformation) {
          try {
            const salt = await bcrypt.genSalt(10);
            const hashPassword = await bcrypt.hash(password, salt);
            const doc = new UserModel({
              name: name,
              email: email,
              password: hashPassword,
              tc: tc,
            });
            await doc.save();

            // implementing JWT
            const saved_user = await UserModel.findOne({ email: email });
            // Generate JWT Token
            const token = jwt.sign(
              { userID: saved_user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );

            res.status(201).json({
              status: "success",
              message: "Registration Success",
              token: token,
            });
          } catch (error) {
            res.send({
              status: "failed",
              message: "unable to register",
            });
          }
        } else {
          res.send({
            status: "failed",
            message: "password and confirm password does'nt match",
          });
        }
      } else {
        res.send({
          status: "failed",
          message: "All Fields are required",
        });
      }
    }
  };

  // Login
  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body;
      if (email && password) {
        const user = await UserModel.findOne({ email: email });
        if (user != null) {
          const isMatch = await bcrypt.compare(password, user.password);
          if (user.email === email && isMatch) {
            //  Generate JWT Token
            const token = jwt.sign(
              { userID: user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );
            res.send({
              status: "success",
              message: "Login Success",
              token: token,
            });
          } else {
            res.send({
              status: "success",
              message: "Email or Password is not valid",
            });
          }
        } else {
          res.send({
            status: "failed",
            message: "You are not registered user",
          });
        }
      } else {
        res.send({
          status: "failed",
          message: "All Fields are required",
        });
      }
    } catch (error) {
      res.send({ status: "failed", message: "Unable to Login" });
    }
  };

  // Change Password

  static changeUserPassword = async (req, res) => {
    const { password, password_conformation } = req.body;

    if (password && password_conformation) {
      if (password !== password_conformation) {
        res.json({
          status: "failed",
          message: "Password and confirm password does not match",
        });
      } else {
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        await UserModel.findByIdAndUpdate(req.user._id, {
          $set: { password: hashPassword },
        });
        // console.log(req.user._id)
        res.json({
          status: "success",
          message: "password change successfully",
        });
      }
    } else {
      res.json({ status: "failed", message: "All Fields are required" });
    }
  };

  // Get Logged user Data
  static loggedUser = async (req, res) => {
    res.json({ user: req.user });
  };

  // send mail to user for reset password
  static sendUserPasswordResetEmail = async (req, res) => {
    const { email } = req.body;

    if (email) {
      const user = await UserModel.findOne({ email: email });

      if (user) {
        const secret = user._id + process.env.JWT_SECRET_KEY;
        const token = jwt.sign({ userID: user._id }, secret, {
          expiresIn: "30m",
        });
        const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`;
        // send email
        let info = await transporter.sendMail({
           from : process.env.EMAIL_FROM,
           to : user.email,
           subject : "coderhouse - password reset link",
           html : `<a href=${link}>click here</a> to reset password`
        }) 
        console.log(link);
        res.json({
          status: "success",
          message: "Password Reset Email Sent... Please Check Your Email",
          email : info
        });
      } else {
        res.json({
          status: "failed",
          message: "Email doesn't exists",
        });
      }
    } else {
      res.json({ status: "failed", message: "Email field is required" });
    }
  };

  // user Password Reset
  static userPasswordReset = async (req, res) => {

    const { password, password_conformation } = req.body;
    const { id, token } = req.params;

    const user = await UserModel.findById(id);
    const new_secret = user._id + process.env.JWT_SECRET_KEY;
    try {
      jwt.verify(token, new_secret);
      if (password && password_conformation) {
        if (password !== password_conformation) {
          res.json({
            status: "failed",
            message: "password and confirm password doesn't match",
          });
        } else {

              const salt = await bcrypt.genSalt(10);
              const hashPassword = await bcrypt.hash(password, salt);
              await UserModel.findByIdAndUpdate(user._id, {
                $set: { password: hashPassword },
              });  
              res.json({
                  status: "success",
                   message: "Password Reset Successfully",
              });
 
        }
      } else {
        res.json({ status: "failed", message: "All Fields are required" });
      }
    } catch (error) {
      res.json({ status: "failed", message: "Invalid Token" });
    }
  };
}

export default UserController;
