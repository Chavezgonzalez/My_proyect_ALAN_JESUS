// models/user.js
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const config = require("../config/config").get(process.env.NODE_ENV);

const SALT_I = 10;

const userSchema = mongoose.Schema({
   email: {
      type: String,
      required: true,
      trim: true,
      unique: 1,
   },
   password: {
      type: String,
      required: true,
      minlength: 6,
   },
   firstname: {
      type: String,
      maxlength: 100,
   },
   lastname: {
      type: String,
      maxlength: 100,
   },
   token: {
      type: String,
   },
});

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre("save", async function (next) {
   const user = this;

   if (!user.isModified("password")) return next();

   try {
      const salt = await bcrypt.genSalt(SALT_I);
      const hash = await bcrypt.hash(user.password, salt);
      user.password = hash;
   } catch (error) {
      console.log(error);
      next(error);
   }
});

// Método para comparar contraseñas en el Login
userSchema.methods.comparepassword = function (candidatePassword) {
   try {
      const isMatch = bcrypt.compareSync(candidatePassword, this.password);
      return { e: null, isMatch };
   } catch (e) {
      return { e, isMatch: false };
   }
};

// Generar Token JWT al iniciar sesión
userSchema.methods.generateToken = async function () {
   const user = this;
   const token = jwt.sign(user._id.toHexString(), config.SECRET);
   user.token = token;

   try {
      await user.save();
      return user;
   } catch (error) {
      console.log(error);
      throw error;
   }
};

// Método estático para validar un usuario mediante su Token
userSchema.statics.findByToken = async function (token) {
   try {
      const decode = jwt.verify(token, config.SECRET);
      return await this.findOne({ _id: decode, token: token });
   } catch (error) {
      return null;
   }
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = async function () {
   const user = this;

   try {
      await user.updateOne({ $unset: { token: 1 } });
      return user;
   } catch (error) {
      console.log(error);
      throw error;
   }
};

const User = mongoose.model("User", userSchema);

module.exports = User;
