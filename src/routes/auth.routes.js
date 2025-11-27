import { Router } from "express";
import { registerUser } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userLoginValidators,
  userValidationUser,
} from "../validators/index.js";
import { login } from "../controllers/auth.controller.js";
const router = Router();

router.route("/register").post(userValidationUser(), validate, registerUser);
router.route("/login").post(userLoginValidators(), validate, login);

export default router;
