"use strict";

let userModel = require("./user.model");
var service = require("../../../services/app.services");
var jwt = require("../../../services/jwtHelper.service");
var errHandler = require("../../../util/errorHandler");
var helper = require("../../../util/helper");

const register = async (req, res) => {
  try {
    let {
      email,
    } = req.body;
    let obj = {};
    let Errors = [];
    let exist = await userModel.findOne({ email: email });
    if (exist && exist._id) {
      return res.status(409).json({
        status: 0,
        message: "Email is already in use!",
      });
    }
    // if (!account_type || account_type == "") {
    //   return res.status(400).json({
    //     status: 0,
    //     message: "account_type  field missing for admin:0/customer:1",
    //   });
    // }
      for (let [key, value] of Object.entries(req.body)) {
        
          if (!value && value == "") {
            Errors.push({ name: key, message: key + "is required" });
          }
        
      }
      if (Errors.length != 0) {
        return res.status(400).json({
          Errors,
        });
      }
  
        obj = {
          ...req.body,
          email: email.toLowerCase()
          }
    const user = new userModel(obj);
    let result = await user.save();
    return res.status(200).json({
      status: 1,
      message: "User Register Successfully",
    });
  } catch (err) {
    let error = errHandler.handle(err);
    return res.status(403).json({
      status: 0,
      message: error,
    });
  }
};

const auth = async (req, res) => {
  try {
    let { email, password, device_token } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: false,
        message: "All fields are required",
      });
    }
    let result = await userModel.findOne({
      email: req.body.email.toLowerCase(),
    });
    if (result && result._id) {
      let compare_result = await service.comparePassword(
        req.body.password,
        result.password
      );

      let token = await jwt.generateToken(
        {
          id: result._id,
          email: result.email.toLowerCase(),
        },
        "login"
      );
      await userModel.updateOne(
        {
          _id: result._id,
        },
        {
          $set: {
            accessToken: token,
            device_token: device_token,
          },
        },
        {
          runValidators: true,
        }
      );
      if (compare_result && token) {
        var finalData = JSON.stringify(result);
        finalData = JSON.parse(finalData);
        delete finalData["password"];
        // delete finalData["_id"];
        delete finalData["creationDate"];
        delete finalData["__v"];
        Object.assign(finalData, { accessToken: token });
        // firebaseService.sendNotification(device_token);
        return res.status(200).json({
          status: true,
          message: "login successfully",
          data: finalData,
        });
      } else {
        return res.status(404).json({
          status: false,
          message: "Invalid Creditials",
        });
      }
    }
    return res.status(404).json({
      message: "Email is not registered please visit registration page",
    });
  } catch (err) {
    let error = errHandler.handle(err);
    return res.status(500).json(error);
  }
};

const forget = async (req, res) => {
  try {
    let { update_password ,mobile} = req.body;
    let Update = await userModel.findOne({
      mobile:mobile,
    });
    Update.password = update_password;
    await Update.save().then(() => {
      return res.status(200).json({
        status: true,
        message: "Password update successfully",
      });
    });

  } catch (error) {
    return res.status(500).json(error);
  }
};

const user_info = async (req, res) => {
  try {
    var finalData = JSON.stringify(req.user);
    finalData = JSON.parse(finalData);
    delete finalData["password"];
    delete finalData["_id"];
    delete finalData["creationDate"];
    delete finalData["__v"];
    return res.status(200).json({
      status: true,
      message: "Authenticated",
      data: finalData,
    });
  } catch (error) {
    return res.status(500).json(error);
  }
};

const logout = async (req, res) => {
  try {
    let Update = await userModel.findOne({
      email: req.user.email.toLowerCase(),
    });
    Update.accessToken = "";
    Update.device_token = "";
    await Update.save().then(() => {
      return res.status(200).json({
        status: true,
        message: "Logout Successfully",
      });
    });
  } catch (error) {
    return res.status(500).json(error);
  }
};

const delete_account = async (req, res) => {
  try {
    let User = await userModel.findOne({
      email: req.user.email.toLowerCase(),
    });
    await User.remove();
    return res.status(200).json({
      status: true,
      message: "Your'e Account Deleted Permanently",
    });
  } catch (error) {
    return res.status(500).json(error);
  }
};

const validate_forgetlink = async (req, res) => {
  try {
    let user = await userModel.findOne({
      reset_password_token: req.body.reset_token,
    });
    if (user) {
      let result = await jwt.verifyToken(req.body.reset_token);
      if (result.message == "jwt expired") {
        return res.status(401).json({
          message: "Password reset link has expired",
        });
      } else {
        user.reset_password_token = "";
        await user.save().then(() => {
          return res.status(200).json({
            message: "Token Verified",
          });
        });
      }
    } else {
      return res.status(401).json({
        message: "Password reset link has expired or already used",
      });
    }
  } catch (error) {
    return res.status(500).json(error);
  }
};
const validate_token = async (req, res) => {
  try {
    let user = await userModel.findOne({
      accessToken: req.body.token,
    });
    if (user) {
      let result = await jwt.verifyToken(req.body.token);
      if (result.message == "jwt expired") {
        return res.status(401).json({
          status: false,
          message: "Access Token has expired",
        });
      } else {
        user.accessToken = "";
        await user.save().then(() => {
          return res.status(200).json({
            status: true,
            message: "Token Verified",
          });
        });
      }
    } else {
      return res.status(401).json({
        message: "Access Token Not found",
      });
    }
  } catch (error) {
    return res.status(500).json(error);
  }
};
const update_password = async (req, res) => {
  try {
    let { update_password, current_password } = req.body;
    let compare_result = await service.comparePassword(
      current_password,
      req.user.password
    );
    if (compare_result) {
      if (update_password == current_password) {
        return res.status(409).json({
          message: "You typed an old password",
        });
      } else {
        let Update = await userModel.findOne({
          email: req.user.email,
        });
        Update.password = update_password;
        await Update.save().then(() => {
          return res.status(200).json({
            status: true,
            message: "Password update successfully",
          });
        });
      }
    }
  } catch (error) {
    return res.status(500).json(error);
  }
};

const verify_password = async (req, res) => {
  try {
    let compare_result = await service.comparePassword(
      req.body.password,
      req.user.password
    );
    if (compare_result) {
    return res.status(200).json({
        status: true,
        message: "Password verified",
      });
    }
    return res.status(401).json({
      status: false,
      message: "You typed the wrong password ",
    });
  } catch (error) {
    return res.status(500).json(error);
  }
};

let getUserProfile = async (req, res) => {
  try {
    let result = await userModel.findOne(
      { _id: req.user._id },
      { accessToken: 0, isApproved: 0, password: 0, terms: 0 }
    );
    return res.status(200).json({ data: result, message: "User Profile" });
  } catch (error) {
    return res.status(500).json({ message: "unexpected error", error: error });
  }
};




let getAllUsers = async (req, res) => {
  try {
      let result = await userModel.find({})
      return res.status(200).json({
        status: true,
        data: result,
        totalResults: totalResults,
        message: "Users",
      });
 
  
  } catch (error) {
    return res.status(500).json({ message: "unexpected error", error: error });
  }
};


module.exports = {
  register: register,
  auth: auth,
  forget: forget,
  user_info: user_info,
  verify_password: verify_password,
  logout: logout,
  delete_account: delete_account,
  validate_forgetlink: validate_forgetlink,
  validate_token: validate_token,
  update_password: update_password,
  getAllUsers: getAllUsers,
  getUserProfile: getUserProfile
};
