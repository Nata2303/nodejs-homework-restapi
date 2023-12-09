
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const gravatar = require("gravatar");
const { v4: uuidv4 } = require("uuid"); // Імпортуйте v4 функцію з пакету uuid
const { sendVerificationEmail } = require("../helpers/sendMail");

const register = async (email, password) => {
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new Error("Email in use");
  }

  const verificationToken = uuidv4();

  const avatarURL = gravatar.url(email, { s: "250", r: "pg", d: "identicon" });

  const newUser = await User.create({
    email,
    password,
    avatarURL,
    verificationToken,
  });
  
  const verificationLink = `http://your_domain.com/users/verify/${verificationToken}`;

    try {
       await sendVerificationEmail(email, verificationLink);
    } catch (error) {
      console.error(error);
      throw new Error("Failed to send verification email");
    }
    return newUser;
  };
  
  const resendVerificationEmail = async (email) => {
    try {
      const user = await User.findOne({ email });

      if (!user) {
        return { success: false, error: "User not found" };
      }

      if (user.verify) {
        return {
          success: false,
          error: "Verification has already been passed",
        };
      }

      const verificationLink = `http://your_domain.com/users/verify/${user.verificationToken}`;

      await sendVerificationEmail(email, verificationLink);

      return { success: true };
    } catch (error) {
      console.error(error);
      return { success: false, error: "Failed to resend verification email" };
    }
  };

  const login = async (email, password) => {
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error("Email or password is wrong");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error("Email or password is wrong");
    }

    const token = jwt.sign({ userId: user._id }, "SECRET_KEY", {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();

    return { token, user };
  };

  const logout = async (userId) => {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error("Not authorized");
    }

    user.token = null;
    await user.save();
  };

  const getCurrentUser = async (userId) => {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error("Not authorized");
    }

    return user;
  };

  const verifyUser = async (verificationToken) => {
    const user = await User.findOneAndUpdate(
      { verificationToken },
      { verify: true, verificationToken: null },
      { new: true }
    );

    return user;
  };

  module.exports = {
    register,
    login,
    logout,
    getCurrentUser,
    verifyUser,
    resendVerificationEmail,
  };